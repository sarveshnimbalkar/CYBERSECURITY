"""Model management. Training must use a known benign baseline period."""
from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.config import settings
from app.core.auth import require_roles
from app.core.auth import Principal
from app.core.audit import record_audit
from app.detection.anomaly import model_status, train_model

router = APIRouter()


@router.get("/model/status", tags=["Model"])
async def get_model_status():
    return model_status()


@router.post("/model/train", tags=["Model"], dependencies=[Depends(require_roles("admin"))])
async def train_baseline(request: Request, include_simulated: bool = False, db: AsyncSession = Depends(get_db), principal: Principal = Depends(require_roles("admin"))):
    if include_simulated and not settings.DEMO_MODE_ENABLED:
        raise HTTPException(status_code=403, detail="Simulated model training requires demo mode")
    try:
        result = await train_model(db, include_simulated=include_simulated)
        record_audit(db, principal, request, "model.train", "model", "isolation_forest", after={"include_simulated": include_simulated, "baseline_source": result.get("baseline_source")})
        return result
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
