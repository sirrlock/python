from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class SecretMeta:
    """Metadata for a stored secret (never contains the value)."""

    key: str
    created_at: int
    read_count: int
    expires_at: int | None = None
    max_reads: int | None = None

    @classmethod
    def from_dict(cls, data: dict) -> SecretMeta:
        return cls(
            key=data["key"],
            created_at=data["created_at"],
            read_count=data["read_count"],
            expires_at=data.get("expires_at"),
            max_reads=data.get("max_reads"),
        )


@dataclass(frozen=True, slots=True)
class AuditEvent:
    """A single audit log entry."""

    id: int
    timestamp: int
    action: str
    source_ip: str
    success: bool
    key: str | None = None
    detail: str | None = None

    @classmethod
    def from_dict(cls, data: dict) -> AuditEvent:
        return cls(
            id=data["id"],
            timestamp=data["timestamp"],
            action=data["action"],
            source_ip=data["source_ip"],
            success=data["success"],
            key=data.get("key"),
            detail=data.get("detail"),
        )


@dataclass(frozen=True, slots=True)
class Webhook:
    """A registered webhook (signing secret redacted)."""

    id: str
    url: str
    events: list[str]
    created_at: int

    @classmethod
    def from_dict(cls, data: dict) -> Webhook:
        return cls(
            id=data["id"],
            url=data["url"],
            events=data["events"],
            created_at=data["created_at"],
        )


@dataclass(frozen=True, slots=True)
class WebhookCreateResult:
    """Result of webhook creation — includes the signing secret (shown once)."""

    id: str
    secret: str

    @classmethod
    def from_dict(cls, data: dict) -> WebhookCreateResult:
        return cls(id=data["id"], secret=data["secret"])


@dataclass(frozen=True, slots=True)
class ApiKey:
    """A scoped API key (hash never returned)."""

    id: str
    label: str
    permissions: list[str]
    created_at: int
    prefix: str | None = None

    @classmethod
    def from_dict(cls, data: dict) -> ApiKey:
        return cls(
            id=data["id"],
            label=data["label"],
            permissions=data["permissions"],
            created_at=data["created_at"],
            prefix=data.get("prefix"),
        )


@dataclass(frozen=True, slots=True)
class ApiKeyCreateResult:
    """Result of API key creation — includes the raw key (shown once)."""

    id: str
    key: str
    label: str
    permissions: list[str]
    prefix: str | None = None

    @classmethod
    def from_dict(cls, data: dict) -> ApiKeyCreateResult:
        return cls(
            id=data["id"],
            key=data["key"],
            label=data["label"],
            permissions=data["permissions"],
            prefix=data.get("prefix"),
        )
