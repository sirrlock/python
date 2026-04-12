from __future__ import annotations

import os
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from urllib.parse import quote

import httpx

from sirr._exceptions import SirrError
from sirr._models import (
    AuditResponse,
    SecretMetadata,
    SecretResponse,
    SecretStatus,
)
from sirr._transport import (
    build_headers,
    handle_response,
    normalize_server,
)


class AsyncSirrClient:
    """Asynchronous Python client for the Sirr ephemeral secret vault."""

    def __init__(self, server: str = "https://sirrlock.com", token: str | None = None) -> None:
        self._base = normalize_server(server)
        self._token = token
        self._client = httpx.AsyncClient(headers=build_headers(token))

    async def __aenter__(self) -> AsyncSirrClient:
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.close()

    async def close(self) -> None:
        await self._client.aclose()

    # ── Secrets ──────────────────────────────────────────────────────────

    async def push(
        self,
        value: str,
        *,
        ttl: int | None = None,
        reads: int | None = None,
        prefix: str | None = None,
    ) -> SecretResponse:
        """Create a secret. Returns metadata including the hash."""
        body: dict = {"value": value}
        if ttl is not None:
            body["ttl_seconds"] = ttl
        if reads is not None:
            body["reads"] = reads
        if prefix is not None:
            body["prefix"] = prefix

        resp = await self._client.post(f"{self._base}/secret", json=body)
        data = handle_response(resp)
        return SecretResponse.from_dict(data)

    async def get(self, hash: str) -> str | None:
        """Read a secret's value. Consumes a read.
        Returns None if 410 (burned/expired/non-existent).
        """
        if not hash:
            raise ValueError("hash must not be empty")

        resp = await self._client.get(f"{self._base}/secret/{quote(hash, safe='')}")
        if resp.status_code == 410:
            return None

        if not resp.is_success:
            raise SirrError(resp.status_code, resp.text)

        return resp.text

    async def inspect(self, hash: str) -> SecretStatus | None:
        """Metadata only via HEAD. Does NOT consume a read."""
        if not hash:
            raise ValueError("hash must not be empty")

        resp = await self._client.head(f"{self._base}/secret/{quote(hash, safe='')}")
        if resp.status_code == 410:
            return None

        if not resp.is_success:
            raise SirrError(resp.status_code, resp.text)

        return SecretStatus.from_headers(dict(resp.headers))

    async def patch(
        self,
        hash: str,
        *,
        value: str | None = None,
        ttl: int | None = None,
        reads: int | None = None,
    ) -> SecretResponse:
        """Update a secret's value/TTL/reads (owner key required)."""
        if not hash:
            raise ValueError("hash must not be empty")

        body: dict = {}
        if value is not None:
            body["value"] = value
        if ttl is not None:
            body["ttl_seconds"] = ttl
        if reads is not None:
            body["reads"] = reads

        resp = await self._client.patch(f"{self._base}/secret/{quote(hash, safe='')}", json=body)
        data = handle_response(resp)
        return SecretResponse.from_dict(data)

    async def burn(self, hash: str) -> None:
        """Burn a secret immediately (DELETE)."""
        if not hash:
            raise ValueError("hash must not be empty")

        resp = await self._client.delete(f"{self._base}/secret/{quote(hash, safe='')}")
        handle_response(resp)

    async def audit(self, hash: str) -> AuditResponse:
        """Get the audit trail for a secret (owner key required)."""
        if not hash:
            raise ValueError("hash must not be empty")

        resp = await self._client.get(f"{self._base}/secret/{quote(hash, safe='')}/audit")
        data = handle_response(resp)
        return AuditResponse.from_dict(data)

    async def list(self) -> list[SecretMetadata]:
        """List all secrets owned by the calling key."""
        resp = await self._client.get(f"{self._base}/secrets")
        data = handle_response(resp)
        return [SecretMetadata.from_dict(s) for s in data]

    async def pull_all(self) -> dict[str, str]:
        """Helper: list all owned secrets and fetch their values.
        Note: consumes a read for each.
        """
        metas = await self.list()
        result: dict[str, str] = {}
        for meta in metas:
            if not meta.burned:
                val = await self.get(meta.hash)
                if val is not None:
                    result[meta.hash] = val
        return result

    @asynccontextmanager
    async def env(self) -> AsyncIterator[None]:
        """Populate os.environ with all owned secrets."""
        secrets = await self.pull_all()
        original: dict[str, str | None] = {}
        for k, v in secrets.items():
            original[k] = os.environ.get(k)
            os.environ[k] = v
        try:
            yield
        finally:
            for k, prev in original.items():
                if prev is None:
                    os.environ.pop(k, None)
                else:
                    os.environ[k] = prev
