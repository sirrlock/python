from __future__ import annotations

import os

import httpx
import pytest
import respx

from sirr import AsyncSirrClient, SecretExistsError, SirrError

# ── push() — public dead-drop ────────────────────────────────────────────────


async def test_push_returns_id(async_client: AsyncSirrClient, mock_api: respx.Router):
    mock_api.post("/secrets").mock(
        return_value=httpx.Response(200, json={"id": "abcd1234" * 8})
    )
    result = await async_client.push("v", ttl=60, reads=2)
    assert result["id"] == "abcd1234" * 8


async def test_push_no_key_in_body(async_client: AsyncSirrClient, mock_api: respx.Router):
    import json

    route = mock_api.post("/secrets").mock(
        return_value=httpx.Response(200, json={"id": "deadbeef" * 8})
    )
    await async_client.push("val")
    parsed = json.loads(route.calls[0].request.content)
    assert "key" not in parsed
    assert parsed["value"] == "val"


# ── set() — org-scoped named secret ─────────────────────────────────────────


async def test_set_returns_key(mock_api: respx.Router):
    mock_api.post("/orgs/myorg/secrets").mock(
        return_value=httpx.Response(200, json={"key": "K"})
    )
    async with AsyncSirrClient(server="https://vault.example.com", token="t", org="myorg") as c:
        result = await c.set("K", "v")
    assert result["key"] == "K"


async def test_set_requires_org(async_client: AsyncSirrClient):
    with pytest.raises(ValueError, match="org"):
        await async_client.set("K", "v")


async def test_set_409_raises_secret_exists_error(mock_api: respx.Router):
    mock_api.post("/orgs/myorg/secrets").mock(
        return_value=httpx.Response(
            409, json={"error": "secret_exists", "message": "secret already exists"}
        )
    )
    async with AsyncSirrClient(server="https://vault.example.com", token="t", org="myorg") as c:
        with pytest.raises(SecretExistsError) as exc_info:
            await c.set("DUPE", "value")
    assert exc_info.value.status == 409


# ── get() — public (by ID) vs org (by key) ──────────────────────────────────


async def test_get_public_by_id(async_client: AsyncSirrClient, mock_api: respx.Router):
    mock_api.get("/secrets/abc123").mock(
        return_value=httpx.Response(200, json={"id": "abc123", "value": "secret"})
    )
    assert await async_client.get("abc123") == "secret"


async def test_get_org_by_key(mock_api: respx.Router):
    mock_api.get("/orgs/myorg/secrets/MY_KEY").mock(
        return_value=httpx.Response(200, json={"key": "MY_KEY", "value": "secret"})
    )
    async with AsyncSirrClient(server="https://vault.example.com", token="t", org="myorg") as c:
        assert await c.get("MY_KEY") == "secret"


async def test_get_not_found(async_client: AsyncSirrClient, mock_api: respx.Router):
    mock_api.get("/secrets/GONE").mock(
        return_value=httpx.Response(404, json={"error": "not found"})
    )
    assert await async_client.get("GONE") is None


async def test_get_error(async_client: AsyncSirrClient, mock_api: respx.Router):
    mock_api.get("/secrets/BAD").mock(return_value=httpx.Response(500, json={"error": "boom"}))
    with pytest.raises(SirrError) as exc_info:
        await async_client.get("BAD")
    assert exc_info.value.status == 500


async def test_delete(async_client: AsyncSirrClient, mock_api: respx.Router):
    mock_api.delete("/secrets/K").mock(return_value=httpx.Response(200, json={"deleted": True}))
    await async_client.delete("K")


async def test_list(async_client: AsyncSirrClient, mock_api: respx.Router):
    mock_api.get("/secrets").mock(
        return_value=httpx.Response(
            200,
            json={
                "secrets": [
                    {"key": "A", "created_at": 1, "read_count": 0, "max_reads": 3},
                ]
            },
        )
    )
    metas = await async_client.list()
    assert len(metas) == 1
    assert metas[0].max_reads == 3


async def test_pull_all_concurrent(async_client: AsyncSirrClient, mock_api: respx.Router):
    mock_api.get("/secrets").mock(
        return_value=httpx.Response(
            200,
            json={
                "secrets": [
                    {"key": "A", "created_at": 1, "read_count": 0},
                    {"key": "B", "created_at": 2, "read_count": 0},
                ]
            },
        )
    )
    mock_api.get("/secrets/A").mock(
        return_value=httpx.Response(200, json={"key": "A", "value": "va"})
    )
    mock_api.get("/secrets/B").mock(
        return_value=httpx.Response(200, json={"key": "B", "value": "vb"})
    )
    result = await async_client.pull_all()
    assert result == {"A": "va", "B": "vb"}


async def test_prune(async_client: AsyncSirrClient, mock_api: respx.Router):
    mock_api.post("/prune").mock(return_value=httpx.Response(200, json={"pruned": 5}))
    assert await async_client.prune() == 5


async def test_env(async_client: AsyncSirrClient, mock_api: respx.Router):
    mock_api.get("/secrets").mock(
        return_value=httpx.Response(
            200,
            json={"secrets": [{"key": "ASYNC_TEST_VAR", "created_at": 1, "read_count": 0}]},
        )
    )
    mock_api.get("/secrets/ASYNC_TEST_VAR").mock(
        return_value=httpx.Response(200, json={"key": "ASYNC_TEST_VAR", "value": "async_val"})
    )

    assert os.environ.get("ASYNC_TEST_VAR") is None
    async with async_client.env():
        assert os.environ["ASYNC_TEST_VAR"] == "async_val"
    assert os.environ.get("ASYNC_TEST_VAR") is None


async def test_async_context_manager():
    with respx.mock(base_url="https://v.test") as router:
        async with AsyncSirrClient(server="https://v.test", token="t") as c:
            router.post("/prune").mock(return_value=httpx.Response(200, json={"pruned": 0}))
            assert await c.prune() == 0
