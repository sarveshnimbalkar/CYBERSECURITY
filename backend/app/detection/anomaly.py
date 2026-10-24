"""Optional Isolation Forest trained on an explicitly chosen benign baseline."""
import asyncio
import math
import os
from datetime import datetime, timezone
from ipaddress import ip_address
from pathlib import Path

import joblib
from sklearn.ensemble import IsolationForest
from sqlalchemy import select, desc
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.models.event import RuntimeEvent


MODEL_VERSION = "1"
MIN_BASELINE_EVENTS = 200
_model: IsolationForest | None = None
_metadata: dict = {}


def features(event: RuntimeEvent) -> list[float]:
    kind = event.event_type
    process = (event.process_name or "").lower().split("/")[-1]
    port = event.destination_port or 0
    try:
        destination = ip_address(event.destination_ip or "")
        external = float(destination.is_global)
    except ValueError:
        external = 0.0
    return [
        float(kind in ("PROCESS_EXEC", "SHELL_EXEC")),
        float(kind == "NET_CONNECT"),
        float(kind in ("FILE_MODIFY", "FILE_DELETE", "FILE_CREATE")),
        float(kind == "PRIV_CHANGE"),
        float(event.user_uid == 0),
        float(process in {"bash", "sh", "zsh", "sudo", "su"}),
        float(process in {"xmrig", "minerd", "cpuminer"}),
        float(port in {1337, 4444, 5555, 6666, 9999, 31337}),
        external,
        min(math.log1p(max(event.bytes_sent or 0, 0)), 20.0),
        float((event.file_path or "").startswith(("/etc/", "/root/", "/proc/"))),
    ]


def load_model() -> None:
    global _model, _metadata
    path = Path(settings.MODEL_PATH)
    if not path.exists():
        return
    saved = joblib.load(path)
    if saved.get("version") != MODEL_VERSION:
        return
    if saved.get("metadata", {}).get("baseline_source") == "baseline_simulated" and not settings.DEMO_MODE_ENABLED:
        return
    _model = saved["model"]
    _metadata = saved["metadata"]


def model_status() -> dict:
    return {"trained": _model is not None, **_metadata}


def score_event(event: RuntimeEvent) -> float | None:
    if _model is None:
        return None
    sample = features(event)
    if _model.predict([sample])[0] != -1:
        return None
    # Score is the distance below the learned decision boundary, capped at 1.
    margin = -float(_model.decision_function([sample])[0])
    return round(min(1.0, max(0.01, margin / 0.2)), 3)


async def train_model(db: AsyncSession, include_simulated: bool = False) -> dict:
    global _model, _metadata
    source = "baseline_simulated" if include_simulated else "baseline_live"
    rows = await db.execute(
        select(RuntimeEvent).where(RuntimeEvent.source == source)
        .order_by(desc(RuntimeEvent.timestamp)).limit(5000)
    )
    baseline = rows.scalars().all()
    if len(baseline) < MIN_BASELINE_EVENTS:
        raise ValueError(f"Need at least {MIN_BASELINE_EVENTS} {source} events; found {len(baseline)}")

    training_data = [features(event) for event in baseline]
    candidate = IsolationForest(n_estimators=150, contamination=0.03, random_state=42)
    await asyncio.to_thread(candidate.fit, training_data)
    metadata = {
        "version": MODEL_VERSION,
        "baseline_source": source,
        "baseline_events": len(baseline),
        "trained_at": datetime.now(timezone.utc).isoformat(),
    }
    path = Path(settings.MODEL_PATH)
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_suffix(".tmp")
    await asyncio.to_thread(joblib.dump, {"version": MODEL_VERSION, "model": candidate, "metadata": metadata}, temp)
    os.replace(temp, path)
    _model = candidate
    _metadata = metadata
    return model_status()
