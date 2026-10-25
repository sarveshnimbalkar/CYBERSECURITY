"""Read-only administrator access to the application audit trail."""
from fastapi import APIRouter, Depends, Query
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.auth import require_roles
from app.core.database import get_db
from app.models.detection import AuditLog

router = APIRouter()


@router.get("/audit", tags=["Audit"], dependencies=[Depends(require_roles("admin"))])
async def list_audit(db: AsyncSession = Depends(get_db), limit: int = Query(100, ge=1, le=500)):
    rows = (await db.execute(select(AuditLog).order_by(AuditLog.timestamp.desc()).limit(limit))).scalars().all()
    return [{
        "id": row.id,
        "timestamp": row.timestamp,
        "actor": row.actor,
        "action": row.action,
        "resource_type": row.resource_type,
        "resource_id": row.resource_id,
        "details": row.details,
        "ip_address": row.ip_address,
        "status": row.status,
    } for row in rows]
