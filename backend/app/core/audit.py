"""Record security-relevant state changes without storing credentials."""
from fastapi import Request
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.auth import Principal
from app.models.detection import AuditLog


def record_audit(
    db: AsyncSession,
    principal: Principal,
    request: Request,
    action: str,
    resource_type: str,
    resource_id: str,
    before: dict | None = None,
    after: dict | None = None,
) -> None:
    db.add(AuditLog(
        actor=principal.name,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        details={"before": before, "after": after},
        ip_address=request.client.host if request.client else None,
        status="SUCCESS",
    ))
