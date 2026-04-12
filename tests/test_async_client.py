from __future__ import annotations

import os
import json
import httpx
import pytest
import respx

from sirr import AsyncSirrClient, SirrError

# ── push() ──────────────────────────────────────────────────────────────────

async def test_push_returns_metadata(async_client: AsyncSirrClient, mock_api: respx.Router):
    mock_api.post("/secret").mock(
        return_value=httpx.Response(201, json={
            "hash": "abc123",
            "url": "http://localhost:7843/secret/abc123",
            "expires_at": 1700003600,
            "reads_remaining": 1,
            "owned": False
        })
    )
    result = await async_client.push("secret-value", ttl=3600, reads=1)
    assert result.hash == "abc123"
    assert result.reads_remaining == 1
    assert result.owned is False

# ── get() ───────────────────────────────────────────────────────────────────

async def test_get_returns_plaintext(async_client: AsyncSirrClient, mock_api: respx.Router):
    mock_api.get("/secret/abc123").mock(
        return_value=httpx.Response(200, content="my-secret")
    )
    assert await async_client.get("abc123") == "my-secret"

async def test_get_410_returns_none(async_client: AsyncSirrClient, mock_api: respx.Router):
    mock_api.get("/secret/GONE").mock(
        return_value=httpx.Response(410, content="Gone")
    )
    assert await async_client.get("GONE") is None

# ── inspect() ───────────────────────────────────────────────────────────────

async def test_inspect_returns_status(async_client: AsyncSirrClient, mock_api: respx.Router):
    mock_api.head("/secret/abc123").mock(
        return_value=httpx.Response(200, headers={
            "x-sirr-created": "2024-01-15T10:00:00Z",
            "x-sirr-reads-remaining": "5",
            "x-sirr-owned": "true"
        })
    )
    status = await async_client.inspect("abc123")
    assert status.reads_remaining == 5
    assert status.owned is True

# ── patch() ─────────────────────────────────────────────────────────────────

async def test_patch_updates_secret(async_client: AsyncSirrClient, mock_api: respx.Router):
    mock_api.patch("/secret/abc123").mock(
        return_value=httpx.Response(200, json={
            "hash": "abc123",
            "url": "http://localhost/secret/abc123",
            "expires_at": 1800000000,
            "reads_remaining": 10,
            "owned": True
        })
    )
    res = await async_client.patch("abc123", value="new", reads=10)
    assert res.reads_remaining == 10

# ── burn() ──────────────────────────────────────────────────────────────────

async def test_burn_deletes_secret(async_client: AsyncSirrClient, mock_api: respx.Router):
    mock_api.delete("/secret/abc123").mock(
        return_value=httpx.Response(204)
    )
    await async_client.burn("abc123")

# ── audit() ─────────────────────────────────────────────────────────────────

async def test_audit_returns_events(async_client: AsyncSirrClient, mock_api: respx.Router):
    mock_api.get("/secret/abc123/audit").mock(
        return_value=httpx.Response(200, json={
            "hash": "abc123",
            "created_at": 1700000000,
            "events": [
                {"type": "secret.create", "at": 1700000000, "ip": "1.2.3.4"}
            ]
        })
    )
    res = await async_client.audit("abc123")
    assert len(res.events) == 1

# ── list() ──────────────────────────────────────────────────────────────────

async def test_list_returns_metas(async_client: AsyncSirrClient, mock_api: respx.Router):
    mock_api.get("/secrets").mock(
        return_value=httpx.Response(200, json=[
            {
                "hash": "abc123",
                "created_at": 1700000000,
                "ttl_expires_at": 1700003600,
                "reads_remaining": 3,
                "burned": False,
                "burned_at": None,
                "owned": True
            }
        ])
    )
    res = await async_client.list()
    assert len(res) == 1
    assert res[0].hash == "abc123"

# ── helpers ─────────────────────────────────────────────────────────────────

async def test_pull_all(async_client: AsyncSirrClient, mock_api: respx.Router):
    mock_api.get("/secrets").mock(
        return_value=httpx.Response(200, json=[
            {"hash": "h1", "created_at": 1, "ttl_expires_at": None, "reads_remaining": None, "burned": False, "burned_at": None, "owned": True}
        ])
    )
    mock_api.get("/secret/h1").mock(return_value=httpx.Response(200, content="v1"))
    res = await async_client.pull_all()
    assert res == {"h1": "v1"}

async def test_env(async_client: AsyncSirrClient, mock_api: respx.Router):
    mock_api.get("/secrets").mock(
        return_value=httpx.Response(200, json=[
            {"hash": "ASYNC_VAR", "created_at": 1, "ttl_expires_at": None, "reads_remaining": None, "burned": False, "burned_at": None, "owned": True}
        ])
    )
    mock_api.get("/secret/ASYNC_VAR").mock(return_value=httpx.Response(200, content="async_val"))

    assert "ASYNC_VAR" not in os.environ
    async with async_client.env():
        assert os.environ["ASYNC_VAR"] == "async_val"
    assert "ASYNC_VAR" not in os.environ
