import httpx
import pytest
import respx

from sirr import (
    ApiKeyCreateResult,
    AsyncSirrClient,
    AuditEvent,
    WebhookCreateResult,
)

BASE = "http://localhost:8080"


@pytest.fixture
def mock_api():
    with respx.mock(base_url=BASE) as api:
        yield api


@pytest.fixture
async def client(mock_api):
    async with AsyncSirrClient(BASE, "test-token") as c:
        yield c


@pytest.mark.asyncio
class TestAsyncAuditLog:
    async def test_get_audit_log(self, client, mock_api):
        event = {
            "id": 1,
            "timestamp": 1000,
            "action": "secret.create",
            "key": "K",
            "source_ip": "127.0.0.1",
            "success": True,
            "detail": None,
        }
        events = [event]
        mock_api.get("/audit").mock(return_value=httpx.Response(200, json={"events": events}))
        result = await client.get_audit_log()
        assert len(result) == 1
        assert isinstance(result[0], AuditEvent)


@pytest.mark.asyncio
class TestAsyncWebhooks:
    async def test_create_webhook(self, client, mock_api):
        mock_api.post("/webhooks").mock(
            return_value=httpx.Response(201, json={"id": "wh_1", "secret": "s3c"})
        )
        result = await client.create_webhook("https://example.com/hook")
        assert isinstance(result, WebhookCreateResult)

    async def test_list_webhooks(self, client, mock_api):
        wh = [
            {
                "id": "wh_1",
                "url": "https://example.com",
                "events": ["*"],
                "created_at": 1000,
            }
        ]
        mock_api.get("/webhooks").mock(return_value=httpx.Response(200, json={"webhooks": wh}))
        result = await client.list_webhooks()
        assert len(result) == 1

    async def test_delete_webhook(self, client, mock_api):
        mock_api.delete("/webhooks/wh_1").mock(
            return_value=httpx.Response(200, json={"deleted": True})
        )
        assert await client.delete_webhook("wh_1") is True


@pytest.mark.asyncio
class TestAsyncApiKeys:
    async def test_create_api_key(self, client, mock_api):
        resp = {
            "id": "abc",
            "key": "sirr_key_123",
            "label": "ci",
            "permissions": ["read"],
            "prefix": None,
        }
        mock_api.post("/keys").mock(return_value=httpx.Response(201, json=resp))
        result = await client.create_api_key("ci", permissions=["read"])
        assert isinstance(result, ApiKeyCreateResult)

    async def test_list_api_keys(self, client, mock_api):
        keys = [
            {
                "id": "abc",
                "label": "ci",
                "permissions": ["read"],
                "prefix": None,
                "created_at": 1000,
            }
        ]
        mock_api.get("/keys").mock(return_value=httpx.Response(200, json={"keys": keys}))
        result = await client.list_api_keys()
        assert len(result) == 1

    async def test_delete_api_key(self, client, mock_api):
        mock_api.delete("/keys/abc").mock(return_value=httpx.Response(200, json={"deleted": True}))
        assert await client.delete_api_key("abc") is True
