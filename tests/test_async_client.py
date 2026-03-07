from __future__ import annotations

import os

import httpx
import pytest
import respx

from sirr import AsyncSirrClient, SirrError


async def test_push(async_client: AsyncSirrClient, mock_api: respx.Router):
    mock_api.post("/secrets").mock(return_value=httpx.Response(200, json={"key": "K"}))
    await async_client.push("K", "v", ttl=60, reads=2)


async def test_get_found(async_client: AsyncSirrClient, mock_api: respx.Router):
    mock_api.get("/secrets/K").mock(
        return_value=httpx.Response(200, json={"key": "K", "value": "secret"})
    )
    assert await async_client.get("K") == "secret"


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
