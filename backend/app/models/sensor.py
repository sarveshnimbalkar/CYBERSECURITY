"""Latest self-reported collector state; absence and staleness are visible."""
from datetime import datetime, timezone

from sqlalchemy import DateTime, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base


class SensorState(Base):
    __tablename__ = "sensor_states"

    sensor_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    hostname: Mapped[str] = mapped_column(String(256))
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    sent_events: Mapped[int] = mapped_column(Integer, default=0)
    dropped_events: Mapped[int] = mapped_column(Integer, default=0)
    parse_failures: Mapped[int] = mapped_column(Integer, default=0)
    queue_depth: Mapped[int] = mapped_column(Integer, default=0)
    restarts: Mapped[int] = mapped_column(Integer, default=0)
