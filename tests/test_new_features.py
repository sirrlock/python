"""Tests for health(), head(), SirrSealed, and updated model fields."""

import httpx
import pytest
import respx

from sirr import (
    AsyncSirrClient,
    SecretHead,
    SecretMeta,
    SirrClient,
    SirrError,
    SirrSealed,
)

BASE = "http://localhost:8080"


@pytest.fixture
def mock_api():
    with respx.mock(base_url=BASE) as api:
        yield api


@pytest.fixture
def client(mock_api):
    with SirrClient(BASE, "test-token") as c:
        yield c


@pytest.fixture
async def async_client(mock_api):
    async with AsyncSirrClient(BASE, "test-token") as c:
        yield c


# ── SecretMeta new fields ─────────────────────────────────────────────────────


class TestSecretMetaFields:
    def test_delete_defaults_true(self):
        meta = SecretMeta.from_dict({"key": "K", "created_at": 1, "read_count": 0})
        assert meta.delete is True

    def test_delete_false(self):
        meta = SecretMeta.from_dict({"key": "K", "created_at": 1, "read_count": 0, "delete": False})
        assert meta.delete is False

    def test_owner_id(self):
        meta = SecretMeta.from_dict(
            {"key": "K", "created_at": 1, "read_count": 0, "owner_id": "p_123"}
        )
        assert meta.owner_id == "p_123"

    def test_owner_id_none(self):
        meta = SecretMeta.from_dict({"key": "K", "created_at": 1, "read_count": 0})
        assert meta.owner_id is None


# ── SirrSealed exception ──────────────────────────────────────────────────────


class TestSirrSealed:
    def test_is_subclass_of_sirr_error(self):
        exc = SirrSealed()
        assert isinstance(exc, SirrError)
        assert exc.status == 410

    def test_custom_message(self):
        exc = SirrSealed("custom sealed message")
        assert "custom sealed message" in str(exc)

    def test_get_raises_sirr_sealed_on_410(self, client, mock_api):
        mock_api.get("/secrets/GONE_KEY").mock(
            return_value=httpx.Response(410, json={"error": "secret is sealed"})
        )
        with pytest.raises(SirrSealed):
            client.get("GONE_KEY")

    def test_patch_raises_sirr_sealed_on_410(self, client, mock_api):
        mock_api.patch("/secrets/GONE_KEY").mock(
            return_value=httpx.Response(410, json={"error": "secret is sealed"})
        )
        with pytest.raises(SirrSealed):
            client.patch("GONE_KEY", value="new")


# ── health() ─────────────────────────────────────────────────────────────────


class TestHealth:
    def test_health_ok(self, client, mock_api):
        mock_api.get("/health").mock(return_value=httpx.Response(200, json={"status": "ok"}))
        assert client.health() is True

    def test_health_down(self, client, mock_api):
        mock_api.get("/health").mock(return_value=httpx.Response(500))
        assert client.health() is False


# ── head() ───────────────────────────────────────────────────────────────────

_HEAD_HEADERS = {
    "x-sirr-read-count": "2",
    "x-sirr-reads-remaining": "3",
    "x-sirr-delete": "true",
    "x-sirr-created-at": "1700000000",
    "x-sirr-status": "active",
}


class TestHead:
    def test_head_active(self, client, mock_api):
        mock_api.head("/secrets/MY_KEY").mock(
            return_value=httpx.Response(200, headers=_HEAD_HEADERS)
        )
        result = client.head("MY_KEY")
        assert isinstance(result, SecretHead)
        assert result.key == "MY_KEY"
        assert result.read_count == 2
        assert result.reads_remaining == 3
        assert result.delete is True
        assert result.created_at == 1700000000
        assert result.sealed is False
        assert result.expires_at is None

    def test_head_sealed(self, client, mock_api):
        headers = {**_HEAD_HEADERS, "x-sirr-reads-remaining": "0", "x-sirr-status": "sealed"}
        mock_api.head("/secrets/SEALED_KEY").mock(return_value=httpx.Response(410, headers=headers))
        result = client.head("SEALED_KEY")
        assert isinstance(result, SecretHead)
        assert result.sealed is True
        assert result.reads_remaining == 0

    def test_head_not_found(self, client, mock_api):
        mock_api.head("/secrets/MISSING").mock(return_value=httpx.Response(404))
        assert client.head("MISSING") is None

    def test_head_unlimited_reads(self, client, mock_api):
        headers = {**_HEAD_HEADERS, "x-sirr-reads-remaining": "unlimited"}
        mock_api.head("/secrets/MY_KEY").mock(return_value=httpx.Response(200, headers=headers))
        result = client.head("MY_KEY")
        assert result.reads_remaining is None

    def test_head_with_expires_at(self, client, mock_api):
        headers = {**_HEAD_HEADERS, "x-sirr-expires-at": "1700003600"}
        mock_api.head("/secrets/MY_KEY").mock(return_value=httpx.Response(200, headers=headers))
        result = client.head("MY_KEY")
        assert result.expires_at == 1700003600

    def test_head_server_error_raises(self, client, mock_api):
        mock_api.head("/secrets/MY_KEY").mock(return_value=httpx.Response(500))
        with pytest.raises(SirrError):
            client.head("MY_KEY")


# ── Async variants ────────────────────────────────────────────────────────────


@pytest.mark.asyncio
class TestAsyncNewFeatures:
    async def test_health_ok(self, async_client, mock_api):
        mock_api.get("/health").mock(return_value=httpx.Response(200, json={"status": "ok"}))
        assert await async_client.health() is True

    async def test_head_active(self, async_client, mock_api):
        mock_api.head("/secrets/MY_KEY").mock(
            return_value=httpx.Response(200, headers=_HEAD_HEADERS)
        )
        result = await async_client.head("MY_KEY")
        assert isinstance(result, SecretHead)
        assert result.sealed is False

    async def test_head_sealed(self, async_client, mock_api):
        headers = {**_HEAD_HEADERS, "x-sirr-status": "sealed"}
        mock_api.head("/secrets/SEALED_KEY").mock(return_value=httpx.Response(410, headers=headers))
        result = await async_client.head("SEALED_KEY")
        assert result.sealed is True

    async def test_get_raises_sirr_sealed(self, async_client, mock_api):
        mock_api.get("/secrets/GONE").mock(
            return_value=httpx.Response(410, json={"error": "sealed"})
        )
        with pytest.raises(SirrSealed):
            await async_client.get("GONE")
