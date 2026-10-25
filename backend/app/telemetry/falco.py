"""Normalize Falco JSON alerts into CloudGuard events."""
from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, Field

from app.schemas import EventIngest


class FalcoAlert(BaseModel):
    event_id: UUID | None = None
    time: datetime
    rule: str = Field(min_length=1, max_length=256)
    priority: str = "Notice"
    output: str = Field(default="", max_length=8192)
    hostname: str = "localhost"
    output_fields: dict[str, Any] = Field(default_factory=dict)


def optional_int(value: Any) -> int | None:
    try:
        return int(value) if value is not None else None
    except (TypeError, ValueError):
        return None


def normalize_alert(alert: FalcoAlert) -> EventIngest:
    fields = alert.output_fields
    syscall = str(fields.get("evt.type", "")).lower()
    open_flags = str(fields.get("evt.arg.flags", "")).lower()
    if syscall in {"execve", "execveat"}:
        event_type = "PROCESS_EXEC"
    elif syscall in {"connect", "sendto", "sendmsg"}:
        event_type = "NET_CONNECT"
    elif syscall in {"open", "openat", "openat2"} and any(
        flag in open_flags for flag in ("wronly", "rdwr", "creat", "trunc")
    ):
        event_type = "FILE_MODIFY"
    elif syscall in {"open", "openat", "openat2"} and open_flags in {"0", "o_rdonly", "rdonly"}:
        event_type = "FILE_READ"
    elif syscall in {"unlink", "unlinkat", "rename", "renameat"}:
        event_type = "FILE_DELETE"
    elif syscall in {"write", "pwrite", "pwrite64"}:
        event_type = "FILE_MODIFY"
    else:
        event_type = "FALCO_ALERT"

    priority = alert.priority.lower()
    severity = (
        "CRITICAL" if priority in {"emergency", "alert", "critical"} else
        "HIGH" if priority in {"error", "warning"} else
        "MEDIUM" if priority == "notice" else "LOW"
    )
    container_id = fields.get("container.id")
    if container_id == "host":
        container_id = None
    return EventIngest(
        event_type=event_type,
        timestamp=alert.time,
        container_id=str(container_id) if container_id else None,
        container_name=fields.get("container.name"),
        container_image=fields.get("container.image") or fields.get("container.image.repository"),
        host=alert.hostname,
        process_name=fields.get("proc.name"),
        process_pid=optional_int(fields.get("proc.pid")),
        parent_process=fields.get("proc.pname"),
        command_line=fields.get("proc.cmdline"),
        user=fields.get("user.name"),
        user_uid=optional_int(fields.get("user.uid")),
        destination_ip=fields.get("fd.rip"),
        destination_port=optional_int(fields.get("fd.rport")),
        protocol=fields.get("fd.l4proto"),
        file_path=fields.get("fd.name"),
        severity=severity,
        source="falco",
        raw_event={
            "rule": alert.rule,
            "priority": alert.priority,
            "output": alert.output,
            "output_fields": fields,
        },
    )
