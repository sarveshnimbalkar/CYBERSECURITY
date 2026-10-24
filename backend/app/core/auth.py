"""A separate shared secret for telemetry writers and dashboard readers."""
import secrets

from fastapi import Header, HTTPException

from app.core.config import settings


async def require_api_key(x_api_key: str | None = Header(default=None)) -> None:
    if not settings.API_KEY or not x_api_key or not secrets.compare_digest(x_api_key, settings.API_KEY):
        raise HTTPException(status_code=401, detail="Invalid API key")
