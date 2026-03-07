import httpx
import pytest
import respx

from sirr import ApiKeyCreateResult, AuditEvent, SirrClient, Webhook, WebhookCreateResult

BASE = "http://localhost:8080"


@pytest.fixture
def mock_api():
    with respx.mock(base_url=BASE) as api:
        yield api


@pytest.fixture
def client(mock_api):
    with SirrClient(BASE, "test-token") as c:
        yield c


class TestAuditLog:
    def test_get_audit_log(self, client, mock_api):
        event = {
            "id": 1,
            "timestamp": 1000,
            "action": "secret.create",
            "key": "K",
            "source_ip": "127.0.0.1",
            "success": True,
            "detail": None,
        }
        mock_api.get("/audit").mock(return_value=httpx.Response(200, json={"events": [event]}))
        result = client.get_audit_log()
        assert len(result) == 1
        assert isinstance(result[0], AuditEvent)
        assert result[0].action == "secret.create"

    def test_get_audit_log_with_params(self, client, mock_api):
        route = mock_api.get("/audit").mock(return_value=httpx.Response(200, json={"events": []}))
        client.get_audit_log(since=100, action="secret.create", limit=10)
        req = route.calls[0].request
        assert "since=100" in str(req.url)
        assert "action=secret.create" in str(req.url)


class TestWebhooks:
    def test_create_webhook(self, client, mock_api):
        mock_api.post("/webhooks").mock(
            return_value=httpx.Response(201, json={"id": "wh_1", "secret": "s3c"})
        )
        result = client.create_webhook("https://example.com/hook")
        assert isinstance(result, WebhookCreateResult)
        assert result.id == "wh_1"

    def test_list_webhooks(self, client, mock_api):
        wh = [{"id": "wh_1", "url": "https://example.com", "events": ["*"], "created_at": 1000}]
        mock_api.get("/webhooks").mock(return_value=httpx.Response(200, json={"webhooks": wh}))
        result = client.list_webhooks()
        assert len(result) == 1
        assert isinstance(result[0], Webhook)

    def test_delete_webhook(self, client, mock_api):
        mock_api.delete("/webhooks/wh_1").mock(
            return_value=httpx.Response(200, json={"deleted": True})
        )
        assert client.delete_webhook("wh_1") is True

    def test_delete_webhook_not_found(self, client, mock_api):
        mock_api.delete("/webhooks/wh_x").mock(
            return_value=httpx.Response(404, json={"error": "not found"})
        )
        assert client.delete_webhook("wh_x") is False


class TestMeKeys:
    def test_create_key(self, client, mock_api):
        resp = {
            "id": "k_abc",
            "name": "ci",
            "key": "sirr_key_123abc",
            "valid_after": 1000,
            "valid_before": 32000000,
        }
        route = mock_api.post("/me/keys").mock(return_value=httpx.Response(201, json=resp))
        result = client.create_key("ci")
        assert isinstance(result, ApiKeyCreateResult)
        assert result.key == "sirr_key_123abc"
        assert result.name == "ci"
        assert result.valid_before == 32000000
        import json

        body = json.loads(route.calls[0].request.content)
        assert body["name"] == "ci"

    def test_create_key_with_ttl(self, client, mock_api):
        resp = {
            "id": "k_abc",
            "name": "temp",
            "key": "sirr_key_xyz",
            "valid_after": 1000,
            "valid_before": 4000,
        }
        route = mock_api.post("/me/keys").mock(return_value=httpx.Response(201, json=resp))
        client.create_key("temp", valid_for_seconds=3600)
        import json

        body = json.loads(route.calls[0].request.content)
        assert body["valid_for_seconds"] == 3600

    def test_delete_key(self, client, mock_api):
        mock_api.delete("/me/keys/k_abc").mock(
            return_value=httpx.Response(200, json={"deleted": True})
        )
        assert client.delete_key("k_abc") is True

    def test_delete_key_not_found(self, client, mock_api):
        mock_api.delete("/me/keys/nope").mock(
            return_value=httpx.Response(404, json={"error": "not found"})
        )
        assert client.delete_key("nope") is False
