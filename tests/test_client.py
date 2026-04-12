from __future__ import annotations

import json
import os

import httpx
import pytest
import respx

from sirr import SirrClient, SirrError

# ── push() ──────────────────────────────────────────────────────────────────


def test_push_returns_metadata(client: SirrClient, mock_api: respx.Router):
    mock_api.post("/secret").mock(
        return_value=httpx.Response(
            201,
            json={
                "hash": "abc123",
                "url": "http://localhost:7843/secret/abc123",
                "expires_at": 1700003600,
                "reads_remaining": 1,
                "owned": False,
            },
        )
    )
    result = client.push("secret-value", ttl=3600, reads=1)
    assert result.hash == "abc123"
    assert result.reads_remaining == 1
    assert result.owned is False


def test_push_with_prefix(client: SirrClient, mock_api: respx.Router):
    route = mock_api.post("/secret").mock(
        return_value=httpx.Response(
            201,
            json={
                "hash": "db_abc123",
                "url": "http://localhost:7843/secret/db_abc123",
                "expires_at": None,
                "reads_remaining": None,
                "owned": True,
            },
        )
    )
    client.push("val", prefix="db_", reads=None)
    sent = json.loads(route.calls[0].request.content)
    assert sent["value"] == "val"
    assert sent["prefix"] == "db_"
    assert "reads" not in sent


# ── get() ───────────────────────────────────────────────────────────────────


def test_get_returns_plaintext(client: SirrClient, mock_api: respx.Router):
    mock_api.get("/secret/abc123").mock(return_value=httpx.Response(200, content="my-secret"))
    assert client.get("abc123") == "my-secret"


def test_get_410_returns_none(client: SirrClient, mock_api: respx.Router):
    mock_api.get("/secret/GONE").mock(return_value=httpx.Response(410, content="Gone"))
    assert client.get("GONE") is None


def test_get_not_found_raises(client: SirrClient, mock_api: respx.Router):
    # In Sirr, 404 is NOT used for missing secrets (410 is used for oracle defense)
    # But if it does happen, it should raise SirrError.
    mock_api.get("/secret/MISSING").mock(return_value=httpx.Response(404, content="Not Found"))
    with pytest.raises(SirrError) as exc:
        client.get("MISSING")
    assert exc.value.status == 404


# ── inspect() ───────────────────────────────────────────────────────────────


def test_inspect_returns_status(client: SirrClient, mock_api: respx.Router):
    mock_api.head("/secret/abc123").mock(
        return_value=httpx.Response(
            200,
            headers={
                "x-sirr-created": "2024-01-15T10:00:00Z",
                "x-sirr-reads-remaining": "5",
                "x-sirr-owned": "true",
            },
        )
    )
    status = client.inspect("abc123")
    assert status.reads_remaining == 5
    assert status.owned is True
    assert status.created == "2024-01-15T10:00:00Z"


def test_inspect_410_returns_none(client: SirrClient, mock_api: respx.Router):
    mock_api.head("/secret/GONE").mock(return_value=httpx.Response(410))
    assert client.inspect("GONE") is None


# ── patch() ─────────────────────────────────────────────────────────────────


def test_patch_updates_secret(client: SirrClient, mock_api: respx.Router):
    mock_api.patch("/secret/abc123").mock(
        return_value=httpx.Response(
            200,
            json={
                "hash": "abc123",
                "url": "http://localhost/secret/abc123",
                "expires_at": 1800000000,
                "reads_remaining": 10,
                "owned": True,
            },
        )
    )
    res = client.patch("abc123", value="new", reads=10)
    assert res.reads_remaining == 10


# ── burn() ──────────────────────────────────────────────────────────────────


def test_burn_deletes_secret(client: SirrClient, mock_api: respx.Router):
    mock_api.delete("/secret/abc123").mock(return_value=httpx.Response(204))
    client.burn("abc123")


# ── audit() ─────────────────────────────────────────────────────────────────


def test_audit_returns_events(client: SirrClient, mock_api: respx.Router):
    mock_api.get("/secret/abc123/audit").mock(
        return_value=httpx.Response(
            200,
            json={
                "hash": "abc123",
                "created_at": 1700000000,
                "events": [
                    {"type": "secret.create", "at": 1700000000, "ip": "1.2.3.4"},
                    {"type": "secret.read", "at": 1700001000, "ip": "1.2.3.4"},
                ],
            },
        )
    )
    res = client.audit("abc123")
    assert len(res.events) == 2
    assert res.events[0].type == "secret.create"


# ── list() ──────────────────────────────────────────────────────────────────


def test_list_returns_metas(client: SirrClient, mock_api: respx.Router):
    mock_api.get("/secrets").mock(
        return_value=httpx.Response(
            200,
            json=[
                {
                    "hash": "abc123",
                    "created_at": 1700000000,
                    "ttl_expires_at": 1700003600,
                    "reads_remaining": 3,
                    "burned": False,
                    "burned_at": None,
                    "owned": True,
                }
            ],
        )
    )
    res = client.list()
    assert len(res) == 1
    assert res[0].hash == "abc123"
    assert res[0].reads_remaining == 3


# ── helpers ─────────────────────────────────────────────────────────────────


def test_pull_all(client: SirrClient, mock_api: respx.Router):
    mock_api.get("/secrets").mock(
        return_value=httpx.Response(
            200,
            json=[
                {
                    "hash": "h1",
                    "created_at": 1,
                    "ttl_expires_at": None,
                    "reads_remaining": None,
                    "burned": False,
                    "burned_at": None,
                    "owned": True,
                },
                {
                    "hash": "h2",
                    "created_at": 1,
                    "ttl_expires_at": None,
                    "reads_remaining": None,
                    "burned": True,
                    "burned_at": 2,
                    "owned": True,
                },
            ],
        )
    )
    mock_api.get("/secret/h1").mock(return_value=httpx.Response(200, content="v1"))
    # h2 is burned, so client.pull_all should not call get() for it or it should be skipped
    res = client.pull_all()
    assert res == {"h1": "v1"}


def test_env_context_manager(client: SirrClient, mock_api: respx.Router):
    mock_api.get("/secrets").mock(
        return_value=httpx.Response(
            200,
            json=[
                {
                    "hash": "VAR1",
                    "created_at": 1,
                    "ttl_expires_at": None,
                    "reads_remaining": None,
                    "burned": False,
                    "burned_at": None,
                    "owned": True,
                }
            ],
        )
    )
    mock_api.get("/secret/VAR1").mock(return_value=httpx.Response(200, content="val1"))

    assert "VAR1" not in os.environ
    with client.env():
        assert os.environ["VAR1"] == "val1"
    assert "VAR1" not in os.environ
