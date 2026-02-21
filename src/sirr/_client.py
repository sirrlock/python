from __future__ import annotations

import os
from collections.abc import Iterator
from contextlib import contextmanager
from urllib.parse import quote

import httpx

from sirr._models import SecretMeta
from sirr._transport import build_headers, handle_response, normalize_server


class SirrClient:
    """Synchronous Python client for the Sirr ephemeral secret vault."""

    def __init__(self, server: str, token: str) -> None:
        self._base = normalize_server(server)
        self._client = httpx.Client(headers=build_headers(token))

    def __enter__(self) -> SirrClient:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def close(self) -> None:
        self._client.close()

    def push(
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
        resp = self._client.post(f"{self._base}/secrets", json=body)
        handle_response(resp)

    def get(self, key: str) -> str | None:
        resp = self._client.get(f"{self._base}/secrets/{quote(key, safe='')}")
        data = handle_response(resp, allow_404=True)
        if data is None:
            return None
        return data["value"]

    def delete(self, key: str) -> None:
        resp = self._client.delete(f"{self._base}/secrets/{quote(key, safe='')}")
        handle_response(resp, allow_404=True)

    def list(self) -> list[SecretMeta]:
        resp = self._client.get(f"{self._base}/secrets")
        data = handle_response(resp)
        return [SecretMeta.from_dict(s) for s in data["secrets"]]

    def pull_all(self) -> dict[str, str]:
        metas = self.list()
        result: dict[str, str] = {}
        for meta in metas:
            value = self.get(meta.key)
            if value is not None:
                result[meta.key] = value
        return result

    def prune(self) -> int:
        resp = self._client.post(f"{self._base}/prune")
        data = handle_response(resp)
        return data["pruned"]

    @contextmanager
    def env(self) -> Iterator[None]:
        secrets = self.pull_all()
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
