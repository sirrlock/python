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
