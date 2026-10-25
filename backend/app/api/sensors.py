"""Collector heartbeat and loss visibility. Counters are self-reported."""
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.auth import require_roles
from app.core.database import get_db
from app.models.sensor import SensorState

router = APIRouter()


class Heartbeat(BaseModel):
    sensor_id: str = Field(min_length=1, max_length=128, pattern=r"^[a-zA-Z0-9_.-]+$")
    hostname: str = Field(min_length=1, max_length=256)
    sent_events: int = Field(ge=0)
    dropped_events: int = Field(ge=0)
    parse_failures: int = Field(ge=0)
    queue_depth: int = Field(ge=0)
    restarts: int = Field(default=0, ge=0)


@router.post("/sensors/heartbeat", tags=["Sensors"], dependencies=[Depends(require_roles("sensor", "admin"))])
async def report_heartbeat(payload: Heartbeat, db: AsyncSession = Depends(get_db)):
    now = datetime.now(timezone.utc)
    sensor = await db.get(SensorState, payload.sensor_id)
    if sensor is None:
        sensor = SensorState(sensor_id=payload.sensor_id)
        db.add(sensor)
    sensor.hostname = payload.hostname
    sensor.last_seen = now
    sensor.sent_events = payload.sent_events
    sensor.dropped_events = payload.dropped_events
    sensor.parse_failures = payload.parse_failures
    sensor.queue_depth = payload.queue_depth
    sensor.restarts = payload.restarts
    return {"sensor_id": payload.sensor_id, "received_at": now}


@router.get("/sensors", tags=["Sensors"], dependencies=[Depends(require_roles("viewer", "analyst", "admin"))])
async def list_sensors(db: AsyncSession = Depends(get_db), stale_after_seconds: int = Query(90, ge=15, le=3600)):
    now = datetime.now(timezone.utc)
    sensors = (await db.execute(select(SensorState).order_by(SensorState.sensor_id))).scalars().all()
    items = []
    for sensor in sensors:
        last_seen = sensor.last_seen.replace(tzinfo=timezone.utc) if sensor.last_seen.tzinfo is None else sensor.last_seen
        age = (now - last_seen).total_seconds()
        items.append({
            "sensor_id": sensor.sensor_id,
            "hostname": sensor.hostname,
            "last_seen": last_seen,
            "age_seconds": round(age, 1),
            "status": "stale" if age > stale_after_seconds else "backlogged" if sensor.queue_depth else "healthy",
            "sent_events": sensor.sent_events,
            "dropped_events": sensor.dropped_events,
            "parse_failures": sensor.parse_failures,
            "queue_depth": sensor.queue_depth,
            "restarts": sensor.restarts,
        })
    return {"status": "unknown" if not items else "degraded" if any(item["status"] != "healthy" for item in items) else "healthy", "sensors": items}
