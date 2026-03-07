from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class SecretMeta:
    """Metadata for a stored secret (never contains the value)."""

    key: str
    created_at: int
    read_count: int
    delete: bool = True
    expires_at: int | None = None
    max_reads: int | None = None
    owner_id: str | None = None

    @classmethod
    def from_dict(cls, data: dict) -> SecretMeta:
        return cls(
            key=data["key"],
            created_at=data["created_at"],
            read_count=data["read_count"],
            delete=data.get("delete", True),
            expires_at=data.get("expires_at"),
            max_reads=data.get("max_reads"),
            owner_id=data.get("owner_id"),
        )


@dataclass(frozen=True, slots=True)
class SecretHead:
    """Metadata returned by HEAD /secrets/:key — does not consume a read."""

    key: str
    read_count: int
    reads_remaining: int | None  # None means unlimited
    delete: bool
    created_at: int
    sealed: bool
    expires_at: int | None = None

    @classmethod
    def from_headers(cls, key: str, headers: dict) -> SecretHead:
        remaining_raw = headers.get("x-sirr-reads-remaining", "unlimited")
        reads_remaining = None if remaining_raw == "unlimited" else int(remaining_raw)
        expires_raw = headers.get("x-sirr-expires-at")
        return cls(
            key=key,
            read_count=int(headers["x-sirr-read-count"]),
            reads_remaining=reads_remaining,
            delete=headers.get("x-sirr-delete", "true").lower() == "true",
            created_at=int(headers["x-sirr-created-at"]),
            sealed=headers.get("x-sirr-status") == "sealed",
            expires_at=int(expires_raw) if expires_raw else None,
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
class ApiKeyCreateResult:
    """Result of key creation via POST /me/keys — includes the raw key (shown once)."""

    id: str
    name: str
    key: str
    valid_after: int
    valid_before: int

    @classmethod
    def from_dict(cls, data: dict) -> ApiKeyCreateResult:
        return cls(
            id=data["id"],
            name=data["name"],
            key=data["key"],
            valid_after=data["valid_after"],
            valid_before=data["valid_before"],
        )


@dataclass(frozen=True, slots=True)
class Principal:
    """A principal (user or service account) within an org."""

    id: str
    name: str
    role: str
    org_id: str
    metadata: dict | None = None
    created_at: int | None = None

    @classmethod
    def from_dict(cls, data: dict) -> Principal:
        return cls(
            id=data["id"],
            name=data["name"],
            role=data["role"],
            org_id=data["org_id"],
            metadata=data.get("metadata"),
            created_at=data.get("created_at"),
        )


@dataclass(frozen=True, slots=True)
class Org:
    """An organization."""

    id: str
    name: str
    created_at: int | None = None
    metadata: dict | None = None

    @classmethod
    def from_dict(cls, data: dict) -> Org:
        return cls(
            id=data["id"],
            name=data["name"],
            created_at=data.get("created_at"),
            metadata=data.get("metadata"),
        )


@dataclass(frozen=True, slots=True)
class Role:
    """A role within an org. `permissions` is a letter-string (e.g. 'RW')."""

    name: str
    permissions: str
    org_id: str | None = None
    built_in: bool = False
    created_at: int | None = None

    @classmethod
    def from_dict(cls, data: dict) -> Role:
        return cls(
            name=data["name"],
            permissions=data["permissions"],
            org_id=data.get("org_id"),
            built_in=data.get("built_in", False),
            created_at=data.get("created_at"),
        )


@dataclass(frozen=True, slots=True)
class MeInfo:
    """Current authenticated principal info."""

    id: str
    name: str
    role: str
    org_id: str
    metadata: dict | None = None
    created_at: int | None = None
    keys: list | None = None

    @classmethod
    def from_dict(cls, data: dict) -> MeInfo:
        return cls(
            id=data["id"],
            name=data["name"],
            role=data["role"],
            org_id=data["org_id"],
            metadata=data.get("metadata"),
            created_at=data.get("created_at"),
            keys=data.get("keys"),
        )
