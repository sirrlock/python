from __future__ import annotations

import asyncio
import os
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from urllib.parse import quote

import httpx

from sirr._models import (
    ApiKey,
    ApiKeyCreateResult,
    AuditEvent,
    SecretMeta,
    Webhook,
    WebhookCreateResult,
)
from sirr._transport import build_headers, handle_response, normalize_server


class AsyncSirrClient:
    """Asynchronous Python client for the Sirr ephemeral secret vault."""

    def __init__(self, server: str, token: str) -> None:
        self._base = normalize_server(server)
        self._client = httpx.AsyncClient(headers=build_headers(token))

    async def __aenter__(self) -> AsyncSirrClient:
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.close()

    async def close(self) -> None:
        await self._client.aclose()

    async def push(
        self,
        key: str,
        value: str,
        *,
        ttl: int | None = None,
        reads: int | None = None,
    ) -> None:
        body: dict = {"key": key, "value": value}
        if ttl is not None:
            body["ttl_seconds"] = ttl
        if reads is not None:
            body["max_reads"] = reads
        resp = await self._client.post(f"{self._base}/secrets", json=body)
        handle_response(resp)

    async def get(self, key: str) -> str | None:
        resp = await self._client.get(f"{self._base}/secrets/{quote(key, safe='')}")
        data = handle_response(resp, allow_404=True)
        if data is None:
            return None
        return data["value"]

    async def delete(self, key: str) -> None:
        resp = await self._client.delete(f"{self._base}/secrets/{quote(key, safe='')}")
        handle_response(resp, allow_404=True)

    async def list(self) -> list[SecretMeta]:
        resp = await self._client.get(f"{self._base}/secrets")
        data = handle_response(resp)
        return [SecretMeta.from_dict(s) for s in data["secrets"]]

    async def pull_all(self) -> dict[str, str]:
        metas = await self.list()

        async def _fetch(meta: SecretMeta) -> tuple[str, str | None]:
            value = await self.get(meta.key)
            return (meta.key, value)

        pairs = await asyncio.gather(*[_fetch(m) for m in metas])
        return {k: v for k, v in pairs if v is not None}

    async def prune(self) -> int:
        resp = await self._client.post(f"{self._base}/prune")
        data = handle_response(resp)
        return data["pruned"]

    @asynccontextmanager
    async def env(self) -> AsyncIterator[None]:
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

    async def get_audit_log(
        self,
        *,
        since: int | None = None,
        until: int | None = None,
        action: str | None = None,
        limit: int | None = None,
    ) -> list[AuditEvent]:
        params: dict[str, str] = {}
        if since is not None:
            params["since"] = str(since)
        if until is not None:
            params["until"] = str(until)
        if action is not None:
            params["action"] = action
        if limit is not None:
            params["limit"] = str(limit)
        resp = await self._client.get(f"{self._base}/audit", params=params)
        data = handle_response(resp)
        return [AuditEvent.from_dict(e) for e in data["events"]]

    async def create_webhook(
        self,
        url: str,
        *,
        events: list[str] | None = None,
    ) -> WebhookCreateResult:
        body: dict = {"url": url}
        if events is not None:
            body["events"] = events
        resp = await self._client.post(f"{self._base}/webhooks", json=body)
        data = handle_response(resp)
        return WebhookCreateResult.from_dict(data)

    async def list_webhooks(self) -> list[Webhook]:
        resp = await self._client.get(f"{self._base}/webhooks")
        data = handle_response(resp)
        return [Webhook.from_dict(w) for w in data["webhooks"]]

    async def delete_webhook(self, id: str) -> bool:
        resp = await self._client.delete(f"{self._base}/webhooks/{quote(id, safe='')}")
        result = handle_response(resp, allow_404=True)
        return result is not None

    async def create_api_key(
        self,
        label: str,
        *,
        permissions: list[str] | None = None,
        prefix: str | None = None,
    ) -> ApiKeyCreateResult:
        body: dict = {"label": label, "permissions": permissions or ["read", "write"]}
        if prefix is not None:
            body["prefix"] = prefix
        resp = await self._client.post(f"{self._base}/keys", json=body)
        data = handle_response(resp)
        return ApiKeyCreateResult.from_dict(data)

    async def list_api_keys(self) -> list[ApiKey]:
        resp = await self._client.get(f"{self._base}/keys")
        data = handle_response(resp)
        return [ApiKey.from_dict(k) for k in data["keys"]]

    async def delete_api_key(self, id: str) -> bool:
        resp = await self._client.delete(f"{self._base}/keys/{quote(id, safe='')}")
        result = handle_response(resp, allow_404=True)
        return result is not None
