from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True, slots=True)
class SecretResponse:
    """Response from POST /secret and PATCH /secret/{hash}."""

    hash: str
    url: str
    expires_at: int | None
    reads_remaining: int | None
    owned: bool

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> SecretResponse:
        return cls(
            hash=data["hash"],
            url=data["url"],
            expires_at=data.get("expires_at"),
            reads_remaining=data.get("reads_remaining"),
            owned=data.get("owned", False),
        )


@dataclass(frozen=True, slots=True)
class SecretStatus:
    """Metadata returned by HEAD /secret/{hash}. Does not consume a read."""

    created: str
    ttl_expires: str | None
    reads_remaining: int | None
    owned: bool

    @classmethod
    def from_headers(cls, headers: dict[str, str]) -> SecretStatus:
        reads_raw = headers.get("x-sirr-reads-remaining")
        return cls(
            created=headers.get("x-sirr-created", ""),
            ttl_expires=headers.get("x-sirr-ttl-expires"),
            reads_remaining=int(reads_raw) if reads_raw is not None else None,
            owned=headers.get("x-sirr-owned") == "true",
        )


@dataclass(frozen=True, slots=True)
class AuditEvent:
    """Single audit event from GET /secret/{hash}/audit."""

    type: str
    at: int
    ip: str

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> AuditEvent:
        return cls(
            type=data["type"],
            at=data["at"],
            ip=data["ip"],
        )


@dataclass(frozen=True, slots=True)
class AuditResponse:
    """Response from GET /secret/{hash}/audit."""

    hash: str
    created_at: int
    events: list[AuditEvent]

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> AuditResponse:
        return cls(
            hash=data["hash"],
            created_at=data["created_at"],
            events=[AuditEvent.from_dict(e) for e in data.get("events", [])],
        )


@dataclass(frozen=True, slots=True)
class SecretMetadata:
    """Metadata for a secret from GET /secrets."""

    hash: str
    created_at: int
    ttl_expires_at: int | None
    reads_remaining: int | None
    burned: bool
    burned_at: int | None
    owned: bool

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> SecretMetadata:
        return cls(
            hash=data["hash"],
            created_at=data["created_at"],
            ttl_expires_at=data.get("ttl_expires_at"),
            reads_remaining=data.get("reads_remaining"),
            burned=data.get("burned", False),
            burned_at=data.get("burned_at"),
            owned=data.get("owned", False),
        )
