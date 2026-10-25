"""Idempotency receipts for retried Falco deliveries."""
from sqlalchemy import ForeignKey, String
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base


class FalcoReceipt(Base):
    __tablename__ = "falco_receipts"

    event_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    runtime_event_id: Mapped[str] = mapped_column(String(64), ForeignKey("runtime_events.id"), nullable=False)
