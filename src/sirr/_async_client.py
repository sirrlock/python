from __future__ import annotations

import asyncio
import os
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from urllib.parse import quote

import httpx

from sirr._models import (
    ApiKeyCreateResult,
    AuditEvent,
    MeInfo,
    Org,
    Principal,
    Role,
    SecretHead,
    SecretMeta,
    Webhook,
    WebhookCreateResult,
)
from sirr._transport import (
    audit_prefix,
    build_headers,
    handle_response,
    normalize_server,
    prune_prefix,
    secrets_prefix,
    webhooks_prefix,
)


class AsyncSirrClient:
    """Asynchronous Python client for the Sirr ephemeral secret vault."""

    def __init__(self, server: str, token: str, *, org: str | None = None) -> None:
        self._base = normalize_server(server)
        self._org = org
        self._client = httpx.AsyncClient(headers=build_headers(token))

    async def __aenter__(self) -> AsyncSirrClient:
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.close()

    async def close(self) -> None:
        await self._client.aclose()

    # ── Health ───────────────────────────────────────────────────────────

    async def health(self) -> bool:
        """Return True if the server is reachable and healthy."""
        try:
            resp = await self._client.get(f"{self._base}/health")
            return resp.is_success
        except Exception:
            return False

    # ── Secrets ──────────────────────────────────────────────────────────

    async def push(
        self,
        value: str,
        *,
        ttl: int | None = None,
        reads: int | None = None,
    ) -> dict:
        """Public dead-drop push — no key, returns {"id": "<hex64>"}."""
        body: dict = {"value": value}
        if ttl is not None:
            body["ttl_seconds"] = ttl
        if reads is not None:
            body["max_reads"] = reads
        resp = await self._client.post(f"{self._base}/secrets", json=body)
        return handle_response(resp)

    async def set(
        self,
        key: str,
        value: str,
        *,
        org: str | None = None,
        ttl: int | None = None,
        reads: int | None = None,
        delete: bool | None = None,
        webhook_url: str | None = None,
        allowed_keys: list[str] | None = None,
    ) -> dict:
        """Org-scoped named secret — requires org.  Returns {"key": "<key>"}."""
        effective_org = org or self._org
        if effective_org is None:
            raise ValueError("set() requires an org — pass org= to set() or to AsyncSirrClient()")
        body: dict = {"key": key, "value": value}
        if ttl is not None:
            body["ttl_seconds"] = ttl
        if reads is not None:
            body["max_reads"] = reads
        if delete is not None:
            body["delete"] = delete
        if webhook_url is not None:
            body["webhook_url"] = webhook_url
        if allowed_keys is not None:
            body["allowed_keys"] = allowed_keys
        url = f"{self._base}/orgs/{quote(effective_org, safe='')}/secrets"
        resp = await self._client.post(url, json=body)
        return handle_response(resp)

    async def get(self, id_or_key: str, *, org: str | None = None) -> str | None:
        """Fetch a secret value.

        Without org: routes to GET /secrets/{id} (public dead-drop, by ID).
        With org (via parameter or client config): routes to GET /orgs/{org}/secrets/{key}.
        Returns None if the secret does not exist or has expired.
        """
        effective_org = org or self._org
        if effective_org is None:
            url = f"{self._base}/secrets/{quote(id_or_key, safe='')}"
        else:
            org_slug = quote(effective_org, safe="")
            key_slug = quote(id_or_key, safe="")
            url = f"{self._base}/orgs/{org_slug}/secrets/{key_slug}"
        resp = await self._client.get(url)
        data = handle_response(resp, allow_404=True)
        if data is None:
            return None
        return data["value"]

    async def patch(
        self,
        key: str,
        *,
        value: str | None = None,
        ttl: int | None = None,
        reads: int | None = None,
    ) -> SecretMeta | None:
        body: dict = {}
        if value is not None:
            body["value"] = value
        if ttl is not None:
            body["ttl_seconds"] = ttl
        if reads is not None:
            body["max_reads"] = reads
        prefix = secrets_prefix(self._base, self._org)
        resp = await self._client.patch(f"{prefix}/{quote(key, safe='')}", json=body)
        data = handle_response(resp, allow_404=True)
        if data is None:
            return None
        return SecretMeta.from_dict(data)

    async def delete(self, key: str) -> None:
        prefix = secrets_prefix(self._base, self._org)
        resp = await self._client.delete(f"{prefix}/{quote(key, safe='')}")
        handle_response(resp, allow_404=True)

    async def head(self, key: str) -> SecretHead | None:
        """Fetch secret metadata without consuming a read.

        Returns None if the secret does not exist or has expired.
        Returns a SecretHead with sealed=True if reads are exhausted (HTTP 410).
        Never raises SirrSealed — use head() to inspect sealed secrets.
        """
        prefix = secrets_prefix(self._base, self._org)
        resp = await self._client.head(f"{prefix}/{quote(key, safe='')}")
        if resp.status_code == 404:
            return None
        if resp.status_code in (200, 410):
            return SecretHead.from_headers(key, dict(resp.headers))
        from sirr._exceptions import SirrError

        raise SirrError(resp.status_code, resp.text)

    async def list(self) -> list[SecretMeta]:
        prefix = secrets_prefix(self._base, self._org)
        resp = await self._client.get(prefix)
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
        prefix = prune_prefix(self._base, self._org)
        resp = await self._client.post(prefix)
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

    # ── Audit ────────────────────────────────────────────────────────────

    async def get_audit_log(
        self,
        *,
        since: int | None = None,
        until: int | None = None,
        action: str | None = None,
        key: str | None = None,
        limit: int | None = None,
    ) -> list[AuditEvent]:
        params: dict[str, str] = {}
        if since is not None:
            params["since"] = str(since)
        if until is not None:
            params["until"] = str(until)
        if action is not None:
            params["action"] = action
        if key is not None:
            params["key"] = key
        if limit is not None:
            params["limit"] = str(limit)
        prefix = audit_prefix(self._base, self._org)
        resp = await self._client.get(prefix, params=params)
        data = handle_response(resp)
        return [AuditEvent.from_dict(e) for e in data["events"]]

    # ── Webhooks ─────────────────────────────────────────────────────────

    async def create_webhook(
        self,
        url: str,
        *,
        events: list[str] | None = None,
    ) -> WebhookCreateResult:
        body: dict = {"url": url}
        if events is not None:
            body["events"] = events
        prefix = webhooks_prefix(self._base, self._org)
        resp = await self._client.post(prefix, json=body)
        data = handle_response(resp)
        return WebhookCreateResult.from_dict(data)

    async def list_webhooks(self) -> list[Webhook]:
        prefix = webhooks_prefix(self._base, self._org)
        resp = await self._client.get(prefix)
        data = handle_response(resp)
        return [Webhook.from_dict(w) for w in data["webhooks"]]

    async def delete_webhook(self, id: str) -> bool:
        prefix = webhooks_prefix(self._base, self._org)
        resp = await self._client.delete(f"{prefix}/{quote(id, safe='')}")
        result = handle_response(resp, allow_404=True)
        return result is not None

    # ── /me ──────────────────────────────────────────────────────────────

    async def me(self) -> MeInfo:
        resp = await self._client.get(f"{self._base}/me")
        data = handle_response(resp)
        return MeInfo.from_dict(data)

    async def update_me(self, *, metadata: dict[str, str] | None = None) -> MeInfo:
        body: dict = {"metadata": metadata or {}}
        resp = await self._client.patch(f"{self._base}/me", json=body)
        data = handle_response(resp)
        return MeInfo.from_dict(data)

    async def create_key(
        self,
        name: str,
        *,
        valid_for_seconds: int | None = None,
        valid_before: int | None = None,
    ) -> ApiKeyCreateResult:
        body: dict = {"name": name}
        if valid_for_seconds is not None:
            body["valid_for_seconds"] = valid_for_seconds
        if valid_before is not None:
            body["valid_before"] = valid_before
        resp = await self._client.post(f"{self._base}/me/keys", json=body)
        data = handle_response(resp)
        return ApiKeyCreateResult.from_dict(data)

    async def delete_key(self, id: str) -> bool:
        resp = await self._client.delete(f"{self._base}/me/keys/{quote(id, safe='')}")
        result = handle_response(resp, allow_404=True)
        return result is not None

    # ── Admin: Orgs ──────────────────────────────────────────────────────

    async def create_org(self, name: str, *, metadata: dict[str, str] | None = None) -> Org:
        body: dict = {"name": name}
        if metadata:
            body["metadata"] = metadata
        resp = await self._client.post(f"{self._base}/orgs", json=body)
        data = handle_response(resp)
        return Org.from_dict(data)

    async def list_orgs(self) -> list[Org]:
        resp = await self._client.get(f"{self._base}/orgs")
        data = handle_response(resp)
        return [Org.from_dict(o) for o in data["orgs"]]

    async def delete_org(self, id: str) -> bool:
        resp = await self._client.delete(f"{self._base}/orgs/{quote(id, safe='')}")
        result = handle_response(resp, allow_404=True)
        return result is not None

    # ── Admin: Principals ────────────────────────────────────────────────

    async def create_principal(
        self,
        org_id: str,
        name: str,
        role: str,
        *,
        metadata: dict[str, str] | None = None,
    ) -> Principal:
        body: dict = {"name": name, "role": role}
        if metadata:
            body["metadata"] = metadata
        resp = await self._client.post(
            f"{self._base}/orgs/{quote(org_id, safe='')}/principals", json=body
        )
        data = handle_response(resp)
        return Principal.from_dict(data)

    async def list_principals(self, org_id: str) -> list[Principal]:
        resp = await self._client.get(f"{self._base}/orgs/{quote(org_id, safe='')}/principals")
        data = handle_response(resp)
        return [Principal.from_dict(p) for p in data["principals"]]

    async def create_principal_key(
        self,
        org_id: str,
        principal_id: str,
        name: str,
        *,
        valid_for_seconds: int | None = None,
    ) -> ApiKeyCreateResult:
        body: dict = {"name": name}
        if valid_for_seconds is not None:
            body["valid_for_seconds"] = valid_for_seconds
        resp = await self._client.post(
            f"{self._base}/orgs/{quote(org_id, safe='')}/principals/{quote(principal_id, safe='')}/keys",
            json=body,
        )
        data = handle_response(resp)
        return ApiKeyCreateResult.from_dict(data)

    async def delete_principal(self, org_id: str, id: str) -> bool:
        resp = await self._client.delete(
            f"{self._base}/orgs/{quote(org_id, safe='')}/principals/{quote(id, safe='')}"
        )
        result = handle_response(resp, allow_404=True)
        return result is not None

    # ── Admin: Roles ─────────────────────────────────────────────────────

    async def create_role(self, org_id: str, name: str, *, permissions: str) -> Role:
        body: dict = {"name": name, "permissions": permissions}
        resp = await self._client.post(
            f"{self._base}/orgs/{quote(org_id, safe='')}/roles", json=body
        )
        data = handle_response(resp)
        return Role.from_dict(data)

    async def list_roles(self, org_id: str) -> list[Role]:
        resp = await self._client.get(f"{self._base}/orgs/{quote(org_id, safe='')}/roles")
        data = handle_response(resp)
        return [Role.from_dict(r) for r in data["roles"]]

    async def delete_role(self, org_id: str, name: str) -> bool:
        resp = await self._client.delete(
            f"{self._base}/orgs/{quote(org_id, safe='')}/roles/{quote(name, safe='')}"
        )
        result = handle_response(resp, allow_404=True)
        return result is not None
