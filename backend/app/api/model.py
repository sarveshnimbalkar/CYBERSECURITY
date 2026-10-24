"""Model management. Training must use a known benign baseline period."""
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.config import settings
from app.detection.anomaly import model_status, train_model

router = APIRouter()


@router.get("/model/status", tags=["Model"])
async def get_model_status():
    return model_status()


@router.post("/model/train", tags=["Model"])
async def train_baseline(include_simulated: bool = False, db: AsyncSession = Depends(get_db)):
    if include_simulated and not settings.DEMO_MODE_ENABLED:
        raise HTTPException(status_code=403, detail="Simulated model training requires demo mode")
    try:
        return await train_model(db, include_simulated=include_simulated)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
