"""
CloudGuard Event Service

Handles event ingestion, normalization, and detection pipeline orchestration.
"""
import uuid
from datetime import datetime, timezone, timedelta
from typing import Optional, List
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, and_, desc

from app.models.event import RuntimeEvent
from app.models.incident import Incident, IncidentNumber
from app.models.detection import Detection, ResponseAction, AuditLog
from app.models.container import Container
from app.schemas import EventIngest
from app.detection.rules import (
    rule_suspicious_shell,
    rule_reverse_shell,
    rule_privilege_escalation,
    rule_suspicious_external_connection,
    rule_cryptomining,
    rule_rapid_file_modification,
    rule_runtime_socket_access,
    rule_credential_file_access,
    rule_cron_persistence,
    rule_security_artifact_tampering,
)
from app.detection.risk_engine import calculate_risk
from app.detection.anomaly import score_event, model_status
from app.detection.rules import DetectionResult
from app.core.config import settings


async def ingest_event(db: AsyncSession, event_data: EventIngest) -> RuntimeEvent:
    """
    Ingest a runtime event, run detection rules, and create incidents as needed.
    This is the main entry point for the detection pipeline.
    """
    # 1. Ensure container exists in registry before event insertion (Foreign Key constraint)
    container = await ensure_container(db, event_data)

    # 2. Create normalized RuntimeEvent record
    event = RuntimeEvent(
        id=str(uuid.uuid4()),
        event_type=event_data.event_type,
        timestamp=event_data.timestamp or datetime.now(timezone.utc),
        container_id=event_data.container_id,
        container_name=event_data.container_name,
        host=event_data.host,
        process_name=event_data.process_name,
        process_pid=event_data.process_pid,
        parent_process=event_data.parent_process,
        parent_pid=event_data.parent_pid,
        command_line=event_data.command_line,
        user=event_data.user,
        user_uid=event_data.user_uid,
        source_ip=event_data.source_ip,
        source_port=event_data.source_port,
        destination_ip=event_data.destination_ip,
        destination_port=event_data.destination_port,
        protocol=event_data.protocol,
        bytes_sent=event_data.bytes_sent,
        bytes_received=event_data.bytes_received,
        file_path=event_data.file_path,
        file_operation=event_data.file_operation,
        severity=event_data.severity,
        source=event_data.source,
        raw_event=event_data.raw_event,
    )
    db.add(event)
    await db.flush()  # get the ID without committing

    # 3. Run rule-based detection
    await run_detection_pipeline(db, event, cpu_percent=container.cpu_percent if container else 0.0)

    return event


async def ensure_container(db: AsyncSession, event_data: EventIngest) -> Optional[Container]:
    """Register container if not seen before."""
    if not event_data.container_id:
        return None

    result = await db.execute(
        select(Container).where(Container.container_id == event_data.container_id)
    )
    container = result.scalar_one_or_none()

    if not container:
        container = Container(
            id=str(uuid.uuid4()),
            container_id=event_data.container_id,
            name=event_data.container_name or event_data.container_id,
            image=event_data.container_image or "unknown",
            host=event_data.host,
            status="running",
            cpu_percent=event_data.cpu_percent or 0.0,
        )
        db.add(container)
    else:
        container.last_seen = datetime.now(timezone.utc)
        if event_data.container_name:
            container.name = event_data.container_name
        if event_data.container_image:
            container.image = event_data.container_image
        if event_data.cpu_percent is not None:
            container.cpu_percent = event_data.cpu_percent

    return container


async def run_detection_pipeline(db: AsyncSession, event: RuntimeEvent, cpu_percent: float = 0.0) -> None:
    """
    Run all detection rules against the event and create incidents for matches.
    """
    # Context: check if recent shell was seen in same container (for RULE-002)
    recent_shell = False
    if event.container_id:
        window_start = datetime.now(timezone.utc) - timedelta(minutes=5)
        shell_result = await db.execute(
            select(func.count(RuntimeEvent.id)).where(
                and_(
                    RuntimeEvent.container_id == event.container_id,
                    RuntimeEvent.event_type.in_(["SHELL_EXEC", "PROCESS_EXEC"]),
                    RuntimeEvent.process_name.in_(["bash", "sh", "zsh", "ash"]),
                    RuntimeEvent.timestamp >= window_start,
                )
            )
        )
        recent_shell = (shell_result.scalar() or 0) > 0

    # Get file mod rate for RULE-006
    file_mod_rate = 0.0
    if event.container_id and event.event_type in ("FILE_MODIFY", "FILE_DELETE", "FILE_CREATE"):
        window_start = datetime.now(timezone.utc) - timedelta(minutes=1)
        mod_result = await db.execute(
            select(func.count(RuntimeEvent.id)).where(
                and_(
                    RuntimeEvent.container_id == event.container_id,
                    RuntimeEvent.event_type.in_(["FILE_MODIFY", "FILE_DELETE", "FILE_CREATE"]),
                    RuntimeEvent.timestamp >= window_start,
                )
            )
        )
        file_mod_rate = float(mod_result.scalar() or 0)

    # Run each rule
    results = [
        rule_suspicious_shell(event),
        rule_reverse_shell(event, recent_shell_in_container=recent_shell),
        rule_privilege_escalation(event),
        rule_suspicious_external_connection(
            event,
            known_destinations={ip.strip() for ip in settings.KNOWN_DESTINATIONS.split(",") if ip.strip()},
        ),
        rule_cryptomining(event, cpu_percent=cpu_percent),
        rule_rapid_file_modification(event, file_mod_rate_per_minute=file_mod_rate),
        rule_runtime_socket_access(event),
        rule_credential_file_access(event),
        rule_cron_persistence(event),
        rule_security_artifact_tampering(event),
    ]
    if event.source == "falco" and event.raw_event and event.raw_event.get("rule"):
        results.append(DetectionResult(
            triggered=True,
            rule_id="FALCO-001",
            rule_name=str(event.raw_event["rule"])[:256],
            severity=event.severity,
            confidence=0.9,
            risk_contribution={"CRITICAL": 50.0, "HIGH": 35.0, "MEDIUM": 20.0, "LOW": 10.0}.get(event.severity, 20.0),
            explanation=str(event.raw_event.get("output", "Falco rule triggered"))[:512],
            indicators=[f"Falco rule: {event.raw_event['rule']}", f"Falco priority: {event.raw_event.get('priority', 'unknown')}"],
            recommended_actions=["Review the Falco alert and process context"],
        ))

    anomaly_score = score_event(event) if event.source not in {"baseline_simulated", "baseline_live"} else None
    if anomaly_score is not None:
        results.append(DetectionResult(
            triggered=True,
            rule_id="ML-001",
            rule_name="Behavioral Anomaly",
            severity="MEDIUM",
            confidence=round(0.5 + anomaly_score * 0.4, 2),
            risk_contribution=15.0,
            explanation=f"Event differs from the trained {settings.APP_NAME} baseline (score {anomaly_score:.3f}).",
            indicators=[f"Isolation Forest anomaly score: {anomaly_score:.3f}"],
            recommended_actions=["Review event context and baseline quality"],
        ))

    triggered = [r for r in results if r.triggered]
    if not triggered:
        return

    correlated_event_count = 1
    if event.container_id:
        related = await db.execute(
            select(func.count(func.distinct(Detection.event_id)))
            .join(RuntimeEvent, Detection.event_id == RuntimeEvent.id)
            .where(and_(
                RuntimeEvent.container_id == event.container_id,
                RuntimeEvent.timestamp >= datetime.now(timezone.utc) - timedelta(minutes=5),
            ))
        )
        correlated_event_count += related.scalar() or 0

    # Calculate risk score
    risk = calculate_risk(
        rule_results=triggered,
        correlated_event_count=correlated_event_count,
        anomaly_score=anomaly_score,
    )

    # Find the highest-severity triggered rule for incident title
    severity_order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
    top_rule = max(triggered, key=lambda r: severity_order.get(r.severity, 0))

    # Create or update incident
    incident = await get_or_create_incident(db, event, top_rule, risk, triggered, anomaly_score)

    # Save detection records
    for rule_result in triggered:
        detection = Detection(
            id=str(uuid.uuid4()),
            event_id=event.id,
            incident_id=incident.id,
            detection_type="ML" if rule_result.rule_id == "ML-001" else "RULE",
            rule_name=rule_result.rule_name,
            rule_id=rule_result.rule_id,
            confidence=rule_result.confidence,
            severity=rule_result.severity,
            risk_score=rule_result.risk_contribution,
            anomaly_score=anomaly_score if rule_result.rule_id == "ML-001" else None,
            is_anomalous=True if rule_result.rule_id == "ML-001" else None,
            model_version=model_status().get("version") if rule_result.rule_id == "ML-001" else None,
            explanation=rule_result.explanation,
            matched_indicators=rule_result.indicators,
            mitre_technique=rule_result.mitre_technique,
            mitre_technique_id=rule_result.mitre_technique_id,
            container_id=event.container_id,
        )
        db.add(detection)

    # Update container risk
    if event.container_id:
        result = await db.execute(
            select(Container).where(Container.container_id == event.container_id)
        )
        container = result.scalar_one_or_none()
        if container:
            container.risk_score = max(container.risk_score, risk.capped_score)
            container.threat_count += 1


async def get_or_create_incident(
    db: AsyncSession, event: RuntimeEvent, top_rule, risk, all_triggered, anomaly_score=None
) -> Incident:
    """
    Find an existing open incident for this container/rule, or create a new one.
    """
    # Look for an open incident for this container in the last 15 minutes
    if event.container_id:
        window = datetime.now(timezone.utc) - timedelta(minutes=15)
        result = await db.execute(
            select(Incident).where(
                and_(
                    Incident.container_id == event.container_id,
                    Incident.status.in_(["OPEN", "INVESTIGATING"]),
                    Incident.detection_rule == top_rule.rule_id,
                    Incident.created_at >= window,
                )
            ).order_by(desc(Incident.created_at)).limit(1)
        )
        existing = result.scalar_one_or_none()
        if existing:
            existing.last_seen = datetime.now(timezone.utc)
            if risk.capped_score > existing.risk_score:
                existing.risk_score = risk.capped_score
                existing.risk_factors = risk.breakdown
                existing.severity = top_rule.severity
            if anomaly_score is not None:
                existing.anomaly_score = max(existing.anomaly_score or 0.0, anomaly_score)
            new_indicators = [item for r in all_triggered for item in r.indicators]
            existing.attack_indicators = list(dict.fromkeys((existing.attack_indicators or []) + new_indicators))[:20]
            existing.updated_at = datetime.now(timezone.utc)
            return existing

    # Let the database allocate a unique display number.
    number = IncidentNumber()
    db.add(number)
    await db.flush()
    incident_number = number.id

    all_indicators = []
    for r in all_triggered:
        all_indicators.extend(r.indicators)

    all_actions = []
    for r in all_triggered:
        all_actions.extend(r.recommended_actions)

    incident = Incident(
        id=str(uuid.uuid4()),
        incident_number=incident_number,
        title=f"{top_rule.rule_name} — {event.container_name or event.container_id or 'Unknown Container'}",
        description=(
            f"Detection rule '{top_rule.rule_name}' triggered on container "
            f"'{event.container_name or event.container_id}'. "
            f"{top_rule.explanation}"
        ),
        severity=top_rule.severity,
        risk_score=risk.capped_score,
        anomaly_score=anomaly_score,
        ml_model_version=model_status().get("version") if anomaly_score is not None else None,
        status="OPEN",
        container_id=event.container_id,
        container_name=event.container_name,
        host=event.host,
        detection_rule=top_rule.rule_id,
        mitre_technique=top_rule.mitre_technique,
        mitre_technique_id=top_rule.mitre_technique_id,
        risk_factors=risk.breakdown,
        attack_indicators=all_indicators[:20],  # cap at 20
        recommended_actions=list(dict.fromkeys(all_actions))[:10],  # deduplicated
        evidence={
            "triggering_event_id": event.id,
            "event_type": event.event_type,
            "process_name": event.process_name,
            "command_line": event.command_line,
            "destination_ip": event.destination_ip,
            "destination_port": event.destination_port,
            "file_path": event.file_path,
        },
    )
    db.add(incident)
    await db.flush()
    return incident
