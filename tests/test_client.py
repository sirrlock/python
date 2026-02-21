from __future__ import annotations

import os

import httpx
import pytest
import respx

from sirr import SirrClient, SirrError


def test_push(client: SirrClient, mock_api: respx.Router):
    mock_api.post("/secrets").mock(return_value=httpx.Response(200, json={"key": "MY_KEY"}))
    client.push("MY_KEY", "secret-value", ttl=600, reads=1)


def test_push_minimal(client: SirrClient, mock_api: respx.Router):
    route = mock_api.post("/secrets").mock(return_value=httpx.Response(200, json={"key": "K"}))
    client.push("K", "v")
    body = route.calls[0].request.content
    import json

    parsed = json.loads(body)
    assert "ttl_seconds" not in parsed
    assert "max_reads" not in parsed


def test_get_found(client: SirrClient, mock_api: respx.Router):
    mock_api.get("/secrets/MY_KEY").mock(
        return_value=httpx.Response(200, json={"key": "MY_KEY", "value": "secret"})
    )
    assert client.get("MY_KEY") == "secret"


def test_get_not_found(client: SirrClient, mock_api: respx.Router):
    mock_api.get("/secrets/GONE").mock(
        return_value=httpx.Response(404, json={"error": "not found"})
    )
    assert client.get("GONE") is None


def test_get_error(client: SirrClient, mock_api: respx.Router):
    mock_api.get("/secrets/BAD").mock(return_value=httpx.Response(500, json={"error": "internal"}))
    with pytest.raises(SirrError) as exc_info:
        client.get("BAD")
    assert exc_info.value.status == 500
    assert "internal" in exc_info.value.message


def test_delete(client: SirrClient, mock_api: respx.Router):
    mock_api.delete("/secrets/MY_KEY").mock(
        return_value=httpx.Response(200, json={"deleted": True})
    )
    client.delete("MY_KEY")


def test_delete_not_found(client: SirrClient, mock_api: respx.Router):
    mock_api.delete("/secrets/GONE").mock(return_value=httpx.Response(404, json={"deleted": False}))
    client.delete("GONE")  # should not raise


def test_list(client: SirrClient, mock_api: respx.Router):
    mock_api.get("/secrets").mock(
        return_value=httpx.Response(
            200,
            json={
                "secrets": [
                    {
                        "key": "A",
                        "created_at": 1000,
                        "read_count": 0,
                        "expires_at": 2000,
                        "max_reads": 5,
                    },
                    {
                        "key": "B",
                        "created_at": 1100,
                        "read_count": 3,
                    },
                ]
            },
        )
    )
    metas = client.list()
    assert len(metas) == 2
    assert metas[0].key == "A"
    assert metas[0].expires_at == 2000
    assert metas[1].max_reads is None


def test_pull_all(client: SirrClient, mock_api: respx.Router):
    mock_api.get("/secrets").mock(
        return_value=httpx.Response(
            200,
            json={
                "secrets": [
                    {"key": "X", "created_at": 1, "read_count": 0},
                    {"key": "Y", "created_at": 2, "read_count": 0},
                ]
            },
        )
    )
    mock_api.get("/secrets/X").mock(
        return_value=httpx.Response(200, json={"key": "X", "value": "vx"})
    )
    mock_api.get("/secrets/Y").mock(return_value=httpx.Response(404, json={"error": "burned"}))
    result = client.pull_all()
    assert result == {"X": "vx"}


def test_prune(client: SirrClient, mock_api: respx.Router):
    mock_api.post("/prune").mock(return_value=httpx.Response(200, json={"pruned": 3}))
    assert client.prune() == 3


def test_env_context_manager(client: SirrClient, mock_api: respx.Router):
    mock_api.get("/secrets").mock(
        return_value=httpx.Response(
            200,
            json={"secrets": [{"key": "SIRR_TEST_VAR", "created_at": 1, "read_count": 0}]},
        )
    )
    mock_api.get("/secrets/SIRR_TEST_VAR").mock(
        return_value=httpx.Response(200, json={"key": "SIRR_TEST_VAR", "value": "injected"})
    )

    assert os.environ.get("SIRR_TEST_VAR") is None
    with client.env():
        assert os.environ["SIRR_TEST_VAR"] == "injected"
    assert os.environ.get("SIRR_TEST_VAR") is None


def test_env_restores_on_exception(client: SirrClient, mock_api: respx.Router):
    mock_api.get("/secrets").mock(
        return_value=httpx.Response(
            200,
            json={"secrets": [{"key": "SIRR_EXC_VAR", "created_at": 1, "read_count": 0}]},
        )
    )
    mock_api.get("/secrets/SIRR_EXC_VAR").mock(
        return_value=httpx.Response(200, json={"key": "SIRR_EXC_VAR", "value": "temp"})
    )

    with pytest.raises(RuntimeError), client.env():
        raise RuntimeError("boom")
    assert os.environ.get("SIRR_EXC_VAR") is None


def test_env_restores_original_value(client: SirrClient, mock_api: respx.Router):
    mock_api.get("/secrets").mock(
        return_value=httpx.Response(
            200,
            json={"secrets": [{"key": "SIRR_ORIG_VAR", "created_at": 1, "read_count": 0}]},
        )
    )
    mock_api.get("/secrets/SIRR_ORIG_VAR").mock(
        return_value=httpx.Response(200, json={"key": "SIRR_ORIG_VAR", "value": "new"})
    )

    os.environ["SIRR_ORIG_VAR"] = "original"
    try:
        with client.env():
            assert os.environ["SIRR_ORIG_VAR"] == "new"
        assert os.environ["SIRR_ORIG_VAR"] == "original"
    finally:
        del os.environ["SIRR_ORIG_VAR"]


def test_context_manager():
    with (
        respx.mock(base_url="https://v.test") as router,
        SirrClient(server="https://v.test", token="t") as c,
    ):
        router.post("/prune").mock(return_value=httpx.Response(200, json={"pruned": 0}))
        assert c.prune() == 0


def test_url_encoding(client: SirrClient, mock_api: respx.Router):
    mock_api.get("/secrets/my%2Fkey").mock(
        return_value=httpx.Response(200, json={"key": "my/key", "value": "v"})
    )
    assert client.get("my/key") == "v"
