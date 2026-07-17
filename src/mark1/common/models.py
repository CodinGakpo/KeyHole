"""The shared data contract.

These models are the lingua franca between the CLI, the MCP server, the control plane, and the
executor. They are defined here, once, so no component invents its own dialect.
"""

from __future__ import annotations

import enum
from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, Field

from mark1.schema.spec import OutputSchema


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class RunStatus(str, enum.Enum):
    PENDING = "pending"
    RUNNING = "running"
    SUCCEEDED = "succeeded"  # ran and produced a schema-conforming, released output
    WITHHELD = "withheld"  # ran but output did not conform / was blocked; nothing released
    FAILED = "failed"  # code errored or infrastructure failure
    TIMEOUT = "timeout"


class Limits(BaseModel):
    """Resource + time bounds applied to a run."""

    timeout_seconds: int = Field(default=60, ge=1, le=900)
    memory_mb: int = Field(default=512, ge=64)
    max_output_bytes: int = Field(default=64 * 1024, ge=1)
    cpu_seconds: int | None = Field(default=None, ge=1)


class RunRequest(BaseModel):
    """A request to run untrusted code against supplied data under a declared exit schema."""

    code: str  # the untrusted Python source
    data: dict[str, str] = Field(default_factory=dict)  # filename -> contents supplied into the box
    output_schema: OutputSchema
    limits: Limits = Field(default_factory=Limits)


class DataFlowEventKind(str, enum.Enum):
    EGRESS_ATTEMPT = "egress_attempt"
    FILE_ACCESS = "file_access"
    OUTPUT_WRITTEN = "output_written"
    LIMIT_HIT = "limit_hit"


class DataFlowEvent(BaseModel):
    """One observed action during a run — the flight-recorder unit."""

    kind: DataFlowEventKind
    detail: str
    denied: bool = False
    at: datetime = Field(default_factory=utcnow)


class RunResult(BaseModel):
    """What a caller gets back for a run."""

    run_id: str
    status: RunStatus
    output: Any | None = None  # the released, schema-conforming value (None if withheld/failed)
    withheld_reason: str | None = None
    exit_bandwidth_bits: float | None = None
    exit_code: int | None = None
    duration_ms: int | None = None
    attestation_id: str | None = None


class AuditRecord(BaseModel):
    """Append-only record of a run, for the audit trail."""

    run_id: str
    created_at: datetime = Field(default_factory=utcnow)
    status: RunStatus
    code_sha256: str
    data_sha256: str
    schema_sha256: str
    output_sha256: str | None = None
    exit_bandwidth_bits: float | None = None
    egress_attempts: int = 0
    egress_denied: int = 0
    dlp_findings: int = 0
    events: list[DataFlowEvent] = Field(default_factory=list)
    attestation_id: str | None = None
    task_arn: str | None = None
