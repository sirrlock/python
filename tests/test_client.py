from __future__ import annotations

import os

import httpx
import pytest
import respx

from sirr import SecretExistsError, SirrClient, SirrError

# ── push() — public dead-drop ────────────────────────────────────────────────


def test_push_returns_id(client: SirrClient, mock_api: respx.Router):
    mock_api.post("/secrets").mock(
        return_value=httpx.Response(200, json={"id": "abcd1234" * 8})
    )
    result = client.push("secret-value", ttl=600, reads=1)
    assert result["id"] == "abcd1234" * 8


def test_push_minimal(client: SirrClient, mock_api: respx.Router):
    import json

    route = mock_api.post("/secrets").mock(
        return_value=httpx.Response(200, json={"id": "deadbeef" * 8})
    )
    client.push("v")
    parsed = json.loads(route.calls[0].request.content)
    assert parsed == {"value": "v"}
    assert "ttl_seconds" not in parsed
    assert "max_reads" not in parsed
    assert "key" not in parsed


def test_push_with_opts(client: SirrClient, mock_api: respx.Router):
    import json

    route = mock_api.post("/secrets").mock(
        return_value=httpx.Response(200, json={"id": "cafebabe" * 8})
    )
    client.push("val", ttl=3600, reads=2)
    parsed = json.loads(route.calls[0].request.content)
    assert parsed["ttl_seconds"] == 3600
    assert parsed["max_reads"] == 2


# ── set() — org-scoped named secret ─────────────────────────────────────────


def test_set_returns_key(mock_api: respx.Router):
    mock_api.post("/orgs/myorg/secrets").mock(
        return_value=httpx.Response(200, json={"key": "MY_KEY"})
    )
    with SirrClient(server="https://vault.example.com", token="t", org="myorg") as c:
        result = c.set("MY_KEY", "secret-value")
    assert result["key"] == "MY_KEY"


def test_set_with_org_param(mock_api: respx.Router):
    import json

    route = mock_api.post("/orgs/acme/secrets").mock(
        return_value=httpx.Response(200, json={"key": "K"})
    )
    with SirrClient(server="https://vault.example.com", token="t") as c:
        c.set("K", "v", org="acme")
    parsed = json.loads(route.calls[0].request.content)
    assert parsed["key"] == "K"
    assert parsed["value"] == "v"


def test_set_requires_org(client: SirrClient):
    with pytest.raises(ValueError, match="org"):
        client.set("K", "v")


def test_set_409_raises_secret_exists_error(mock_api: respx.Router):
    mock_api.post("/orgs/myorg/secrets").mock(
        return_value=httpx.Response(
            409, json={"error": "secret_exists", "message": "secret already exists"}
        )
    )
    with (
        SirrClient(server="https://vault.example.com", token="t", org="myorg") as c,
        pytest.raises(SecretExistsError) as exc_info,
    ):
        c.set("DUPE", "value")
    assert exc_info.value.status == 409


# ── get() — public (by ID) vs org (by key) ──────────────────────────────────


def test_get_public_by_id(client: SirrClient, mock_api: respx.Router):
    mock_api.get("/secrets/abc123").mock(
        return_value=httpx.Response(200, json={"id": "abc123", "value": "secret"})
    )
    assert client.get("abc123") == "secret"


def test_get_public_not_found(client: SirrClient, mock_api: respx.Router):
    mock_api.get("/secrets/GONE").mock(
        return_value=httpx.Response(404, json={"error": "not found"})
    )
    assert client.get("GONE") is None


def test_get_org_by_key(mock_api: respx.Router):
    mock_api.get("/orgs/myorg/secrets/MY_KEY").mock(
        return_value=httpx.Response(200, json={"key": "MY_KEY", "value": "secret"})
    )
    with SirrClient(server="https://vault.example.com", token="t", org="myorg") as c:
        assert c.get("MY_KEY") == "secret"


def test_get_org_via_param(client: SirrClient, mock_api: respx.Router):
    mock_api.get("/orgs/acme/secrets/MY_KEY").mock(
        return_value=httpx.Response(200, json={"key": "MY_KEY", "value": "val"})
    )
    assert client.get("MY_KEY", org="acme") == "val"


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


def test_set_requires_org_no_client_org():
    with pytest.raises(ValueError, match="org"), SirrClient("http://localhost:8080", "t") as c:
        c.set("K", "v")
