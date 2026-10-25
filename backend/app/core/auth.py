"""Scoped API identities. Keys are configured outside the repository."""
from dataclasses import dataclass
from typing import Callable
from collections import deque
import asyncio
import hashlib
import secrets
import time

from fastapi import Depends, Header, HTTPException

from app.core.config import settings


@dataclass(frozen=True)
class Principal:
    name: str
    role: str


_request_times: dict[bytes, deque[float]] = {}
_rate_lock = asyncio.Lock()


async def check_rate_limit(api_key: str, role: str) -> None:
    """Single-process guard; deploy an edge limiter for multiple workers."""
    fingerprint = hashlib.sha256(api_key.encode()).digest()
    limit = 1200 if role == "sensor" else 300
    now = time.monotonic()
    async with _rate_lock:
        times = _request_times.setdefault(fingerprint, deque())
        while times and times[0] <= now - 60:
            times.popleft()
        if len(times) >= limit:
            raise HTTPException(status_code=429, detail="Rate limit exceeded", headers={"Retry-After": "60"})
        times.append(now)


async def get_principal(x_api_key: str | None = Header(default=None)) -> Principal:
    if not x_api_key:
        raise HTTPException(status_code=401, detail="Invalid API key")
    keys = (
        ("admin", settings.ADMIN_API_KEY),
        ("analyst", settings.ANALYST_API_KEY),
        ("viewer", settings.VIEWER_API_KEY),
        ("sensor", settings.SENSOR_API_KEY),
    )
    for role, configured in keys:
        if configured and secrets.compare_digest(x_api_key, configured):
            await check_rate_limit(x_api_key, role)
            return Principal(name=role, role=role)
    # Compatibility for local development only. Production rejects the legacy key.
    if settings.APP_ENV != "production" and settings.API_KEY and secrets.compare_digest(x_api_key, settings.API_KEY):
        await check_rate_limit(x_api_key, "admin")
        return Principal(name="legacy-development", role="admin")
    raise HTTPException(status_code=401, detail="Invalid API key")


def require_roles(*allowed: str) -> Callable:
    async def check(principal: Principal = Depends(get_principal)) -> Principal:
        if principal.role not in allowed:
            raise HTTPException(status_code=403, detail="Insufficient role")
        return principal
    return check
