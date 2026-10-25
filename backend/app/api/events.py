"""Events API — ingest and query runtime events."""
from typing import Optional, List
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException, Query, BackgroundTasks
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc, func

from app.core.database import get_db
from app.core.auth import Principal, require_roles
from app.models.event import RuntimeEvent
from app.models.receipt import FalcoReceipt
from app.schemas import EventIngest, EventResponse
from app.services.event_service import ingest_event
from app.telemetry.falco import FalcoAlert, normalize_alert

router = APIRouter()


@router.post("/falco/events", response_model=EventResponse, status_code=201, tags=["Events"], dependencies=[Depends(require_roles("sensor", "admin"))])
async def ingest_falco_alert(alert: FalcoAlert, db: AsyncSession = Depends(get_db)):
    """Accept Falco JSON alerts through an authenticated forwarder."""
    if alert.event_id:
        receipt = await db.get(FalcoReceipt, str(alert.event_id))
        if receipt:
            event = await db.get(RuntimeEvent, receipt.runtime_event_id)
            if event:
                return event
    event = await ingest_event(db, normalize_alert(alert))
    if alert.event_id:
        db.add(FalcoReceipt(event_id=str(alert.event_id), runtime_event_id=event.id))
    return event


@router.post("/events", response_model=EventResponse, status_code=201, tags=["Events"])
async def ingest_runtime_event(
    event_data: EventIngest,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
    principal: Principal = Depends(require_roles("sensor", "admin")),
):
    """
    Ingest a normalized runtime event into the CloudGuard pipeline.
    Triggers detection rules and creates incidents automatically.
    """
    if event_data.source == "baseline_live" and principal.role != "admin":
        raise HTTPException(status_code=403, detail="Baseline ingestion requires admin role")
    if principal.role == "sensor" and event_data.source in {"simulated", "baseline_simulated"}:
        raise HTTPException(status_code=403, detail="Sensor cannot submit simulated events")
    event = await ingest_event(db, event_data)
    return event


@router.get("/events", response_model=List[EventResponse], tags=["Events"], dependencies=[Depends(require_roles("viewer", "analyst", "admin"))])
async def list_events(
    db: AsyncSession = Depends(get_db),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    container_id: Optional[str] = Query(None),
    event_type: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
):
    """List runtime events with optional filters."""
    stmt = select(RuntimeEvent).order_by(desc(RuntimeEvent.timestamp))

    if container_id:
        stmt = stmt.where(RuntimeEvent.container_id == container_id)
    if event_type:
        stmt = stmt.where(RuntimeEvent.event_type == event_type)
    if severity:
        stmt = stmt.where(RuntimeEvent.severity == severity.upper())

    stmt = stmt.offset((page - 1) * page_size).limit(page_size)
    result = await db.execute(stmt)
    return result.scalars().all()


@router.get("/events/{event_id}", response_model=EventResponse, tags=["Events"], dependencies=[Depends(require_roles("viewer", "analyst", "admin"))])
async def get_event(event_id: str, db: AsyncSession = Depends(get_db)):
    """Get a specific runtime event by ID."""
    result = await db.execute(select(RuntimeEvent).where(RuntimeEvent.id == event_id))
    event = result.scalar_one_or_none()
    if not event:
        raise HTTPException(status_code=404, detail="Event not found")
    return event
