from __future__ import annotations

import json
from typing import ClassVar

import httpx
import pytest
import respx

from sirr import (
    ApiKeyCreateResult,
    AsyncSirrClient,
    MeInfo,
    Org,
    Principal,
    Role,
    SirrClient,
)

SERVER = "https://vault.example.com"
TOKEN = "test-token-abc"
ORG = "acme"
ORG_ID = "org_abc123"


# ── Fixtures ─────────────────────────────────────────────────────────────


@pytest.fixture()
def mock_api():
    with respx.mock(base_url=SERVER) as router:
        yield router


@pytest.fixture()
def org_client(mock_api):
    with SirrClient(server=SERVER, token=TOKEN, org=ORG) as c:
        yield c


@pytest.fixture()
def public_client(mock_api):
    with SirrClient(server=SERVER, token=TOKEN) as c:
        yield c


@pytest.fixture()
async def async_org_client(mock_api):
    async with AsyncSirrClient(server=SERVER, token=TOKEN, org=ORG) as c:
        yield c


@pytest.fixture()
async def async_public_client(mock_api):
    async with AsyncSirrClient(server=SERVER, token=TOKEN) as c:
        yield c


# ── Org-scoped URL tests (sync) ─────────────────────────────────────────


class TestOrgScopedUrls:
    def test_set_uses_org_prefix(self, org_client: SirrClient, mock_api: respx.Router):
        route = mock_api.post(f"/orgs/{ORG}/secrets").mock(
            return_value=httpx.Response(200, json={"key": "K"})
        )
        org_client.set("K", "v")
        assert route.called

    def test_get_uses_org_prefix(self, org_client: SirrClient, mock_api: respx.Router):
        route = mock_api.get(f"/orgs/{ORG}/secrets/K").mock(
            return_value=httpx.Response(200, json={"key": "K", "value": "v"})
        )
        assert org_client.get("K") == "v"
        assert route.called

    def test_delete_uses_org_prefix(self, org_client: SirrClient, mock_api: respx.Router):
        route = mock_api.delete(f"/orgs/{ORG}/secrets/K").mock(
            return_value=httpx.Response(200, json={"deleted": True})
        )
        org_client.delete("K")
        assert route.called

    def test_list_uses_org_prefix(self, org_client: SirrClient, mock_api: respx.Router):
        route = mock_api.get(f"/orgs/{ORG}/secrets").mock(
            return_value=httpx.Response(200, json={"secrets": []})
        )
        org_client.list()
        assert route.called

    def test_prune_uses_org_prefix(self, org_client: SirrClient, mock_api: respx.Router):
        route = mock_api.post(f"/orgs/{ORG}/prune").mock(
            return_value=httpx.Response(200, json={"pruned": 0})
        )
        org_client.prune()
        assert route.called

    def test_audit_uses_org_prefix(self, org_client: SirrClient, mock_api: respx.Router):
        route = mock_api.get(f"/orgs/{ORG}/audit").mock(
            return_value=httpx.Response(200, json={"events": []})
        )
        org_client.get_audit_log()
        assert route.called

    def test_webhooks_uses_org_prefix(self, org_client: SirrClient, mock_api: respx.Router):
        route = mock_api.get(f"/orgs/{ORG}/webhooks").mock(
            return_value=httpx.Response(200, json={"webhooks": []})
        )
        org_client.list_webhooks()
        assert route.called

    def test_create_webhook_uses_org_prefix(self, org_client: SirrClient, mock_api: respx.Router):
        route = mock_api.post(f"/orgs/{ORG}/webhooks").mock(
            return_value=httpx.Response(201, json={"id": "wh_1", "secret": "s"})
        )
        org_client.create_webhook("https://hook.example.com")
        assert route.called

    def test_delete_webhook_uses_org_prefix(self, org_client: SirrClient, mock_api: respx.Router):
        route = mock_api.delete(f"/orgs/{ORG}/webhooks/wh_1").mock(
            return_value=httpx.Response(200, json={"deleted": True})
        )
        org_client.delete_webhook("wh_1")
        assert route.called

    def test_patch_uses_org_prefix(self, org_client: SirrClient, mock_api: respx.Router):
        meta = {"key": "K", "created_at": 1000, "read_count": 1}
        route = mock_api.patch(f"/orgs/{ORG}/secrets/K").mock(
            return_value=httpx.Response(200, json=meta)
        )
        org_client.patch("K", ttl=3600)
        assert route.called


# ── Public bucket (no org) tests ─────────────────────────────────────────


class TestPublicBucketUrls:
    def test_push_no_org(self, public_client: SirrClient, mock_api: respx.Router):
        route = mock_api.post("/secrets").mock(
            return_value=httpx.Response(200, json={"id": "deadbeef" * 8})
        )
        public_client.push("v")
        assert route.called

    def test_push_with_optional_fields(self, public_client: SirrClient, mock_api: respx.Router):
        route = mock_api.post("/secrets").mock(
            return_value=httpx.Response(200, json={"id": "deadbeef" * 8})
        )
        public_client.push("v", ttl=60, reads=1)
        body = json.loads(route.calls[0].request.content)
        assert body["ttl_seconds"] == 60
        assert body["max_reads"] == 1
        assert "key" not in body

    def test_get_no_org(self, public_client: SirrClient, mock_api: respx.Router):
        route = mock_api.get("/secrets/K").mock(
            return_value=httpx.Response(200, json={"key": "K", "value": "v"})
        )
        assert public_client.get("K") == "v"
        assert route.called

    def test_prune_no_org(self, public_client: SirrClient, mock_api: respx.Router):
        route = mock_api.post("/prune").mock(return_value=httpx.Response(200, json={"pruned": 2}))
        assert public_client.prune() == 2
        assert route.called

    def test_audit_no_org(self, public_client: SirrClient, mock_api: respx.Router):
        route = mock_api.get("/audit").mock(return_value=httpx.Response(200, json={"events": []}))
        public_client.get_audit_log()
        assert route.called

    def test_patch_no_org(self, public_client: SirrClient, mock_api: respx.Router):
        meta = {"key": "K", "created_at": 1000, "read_count": 0}
        route = mock_api.patch("/secrets/K").mock(return_value=httpx.Response(200, json=meta))
        result = public_client.patch("K", reads=5)
        assert route.called
        body = json.loads(route.calls[0].request.content)
        assert body["max_reads"] == 5
        assert result is not None
        assert result.key == "K"

    def test_patch_not_found(self, public_client: SirrClient, mock_api: respx.Router):
        mock_api.patch("/secrets/missing").mock(
            return_value=httpx.Response(404, json={"error": "not found"})
        )
        assert public_client.patch("missing", ttl=60) is None


# ── /me methods (sync) ───────────────────────────────────────────────────


class TestMe:
    ME_RESP: ClassVar[dict] = {
        "id": "p_1",
        "name": "alice",
        "role": "reader",
        "org_id": "org_abc",
        "metadata": {},
        "keys": [],
    }

    def test_me(self, public_client: SirrClient, mock_api: respx.Router):
        mock_api.get("/me").mock(return_value=httpx.Response(200, json=self.ME_RESP))
        info = public_client.me()
        assert isinstance(info, MeInfo)
        assert info.id == "p_1"
        assert info.name == "alice"
        assert info.org_id == "org_abc"

    def test_update_me(self, public_client: SirrClient, mock_api: respx.Router):
        updated = {**self.ME_RESP, "metadata": {"team": "eng"}}
        route = mock_api.patch("/me").mock(return_value=httpx.Response(200, json=updated))
        info = public_client.update_me(metadata={"team": "eng"})
        assert info.metadata == {"team": "eng"}
        body = json.loads(route.calls[0].request.content)
        assert body["metadata"] == {"team": "eng"}

    def test_update_me_empty_metadata(self, public_client: SirrClient, mock_api: respx.Router):
        route = mock_api.patch("/me").mock(return_value=httpx.Response(200, json=self.ME_RESP))
        public_client.update_me()
        body = json.loads(route.calls[0].request.content)
        assert body["metadata"] == {}

    def test_create_key(self, public_client: SirrClient, mock_api: respx.Router):
        resp = {
            "id": "k_1",
            "name": "ci",
            "key": "sirr_key_abc",
            "valid_after": 1000,
            "valid_before": 32000000,
        }
        route = mock_api.post("/me/keys").mock(return_value=httpx.Response(201, json=resp))
        result = public_client.create_key("ci")
        assert isinstance(result, ApiKeyCreateResult)
        assert result.key == "sirr_key_abc"
        assert result.name == "ci"
        body = json.loads(route.calls[0].request.content)
        assert body["name"] == "ci"

    def test_delete_key(self, public_client: SirrClient, mock_api: respx.Router):
        mock_api.delete("/me/keys/k_1").mock(
            return_value=httpx.Response(200, json={"deleted": True})
        )
        assert public_client.delete_key("k_1") is True

    def test_delete_key_not_found(self, public_client: SirrClient, mock_api: respx.Router):
        mock_api.delete("/me/keys/k_x").mock(
            return_value=httpx.Response(404, json={"error": "not found"})
        )
        assert public_client.delete_key("k_x") is False


# ── Admin methods (sync) ────────────────────────────────────────────────


class TestAdmin:
    def test_create_org(self, public_client: SirrClient, mock_api: respx.Router):
        route = mock_api.post("/orgs").mock(
            return_value=httpx.Response(201, json={"id": ORG_ID, "name": "Acme"})
        )
        org = public_client.create_org("Acme")
        assert isinstance(org, Org)
        assert org.name == "Acme"
        body = json.loads(route.calls[0].request.content)
        assert body["name"] == "Acme"

    def test_list_orgs(self, public_client: SirrClient, mock_api: respx.Router):
        mock_api.get("/orgs").mock(
            return_value=httpx.Response(200, json={"orgs": [{"id": ORG_ID, "name": "Acme"}]})
        )
        orgs = public_client.list_orgs()
        assert len(orgs) == 1
        assert isinstance(orgs[0], Org)

    def test_delete_org(self, public_client: SirrClient, mock_api: respx.Router):
        mock_api.delete(f"/orgs/{ORG_ID}").mock(
            return_value=httpx.Response(200, json={"deleted": True})
        )
        assert public_client.delete_org(ORG_ID) is True

    def test_delete_org_not_found(self, public_client: SirrClient, mock_api: respx.Router):
        mock_api.delete(f"/orgs/{ORG_ID}").mock(
            return_value=httpx.Response(404, json={"error": "not found"})
        )
        assert public_client.delete_org(ORG_ID) is False

    def test_create_principal(self, public_client: SirrClient, mock_api: respx.Router):
        route = mock_api.post(f"/orgs/{ORG_ID}/principals").mock(
            return_value=httpx.Response(
                201,
                json={"id": "pr_1", "name": "alice", "role": "reader", "org_id": ORG_ID},
            )
        )
        p = public_client.create_principal(ORG_ID, "alice", "reader")
        assert isinstance(p, Principal)
        assert p.name == "alice"
        assert p.org_id == ORG_ID
        body = json.loads(route.calls[0].request.content)
        assert body["name"] == "alice"
        assert body["role"] == "reader"

    def test_list_principals(self, public_client: SirrClient, mock_api: respx.Router):
        mock_api.get(f"/orgs/{ORG_ID}/principals").mock(
            return_value=httpx.Response(
                200,
                json={
                    "principals": [
                        {"id": "pr_1", "name": "alice", "role": "reader", "org_id": ORG_ID}
                    ]
                },
            )
        )
        principals = public_client.list_principals(ORG_ID)
        assert len(principals) == 1
        assert isinstance(principals[0], Principal)

    def test_delete_principal(self, public_client: SirrClient, mock_api: respx.Router):
        mock_api.delete(f"/orgs/{ORG_ID}/principals/pr_1").mock(
            return_value=httpx.Response(200, json={"deleted": True})
        )
        assert public_client.delete_principal(ORG_ID, "pr_1") is True

    def test_delete_principal_not_found(self, public_client: SirrClient, mock_api: respx.Router):
        mock_api.delete(f"/orgs/{ORG_ID}/principals/pr_x").mock(
            return_value=httpx.Response(404, json={"error": "not found"})
        )
        assert public_client.delete_principal(ORG_ID, "pr_x") is False

    def test_create_role(self, public_client: SirrClient, mock_api: respx.Router):
        route = mock_api.post(f"/orgs/{ORG_ID}/roles").mock(
            return_value=httpx.Response(
                201,
                json={"name": "editor", "permissions": "RW", "org_id": ORG_ID},
            )
        )
        role = public_client.create_role(ORG_ID, "editor", permissions="RW")
        assert isinstance(role, Role)
        assert role.name == "editor"
        assert role.permissions == "RW"
        body = json.loads(route.calls[0].request.content)
        assert body["name"] == "editor"
        assert body["permissions"] == "RW"

    def test_list_roles(self, public_client: SirrClient, mock_api: respx.Router):
        mock_api.get(f"/orgs/{ORG_ID}/roles").mock(
            return_value=httpx.Response(
                200,
                json={"roles": [{"name": "editor", "permissions": "RW", "org_id": ORG_ID}]},
            )
        )
        roles = public_client.list_roles(ORG_ID)
        assert len(roles) == 1
        assert isinstance(roles[0], Role)

    def test_delete_role(self, public_client: SirrClient, mock_api: respx.Router):
        mock_api.delete(f"/orgs/{ORG_ID}/roles/editor").mock(
            return_value=httpx.Response(200, json={"deleted": True})
        )
        assert public_client.delete_role(ORG_ID, "editor") is True


# ── Async org-scoped tests ───────────────────────────────────────────────


@pytest.mark.asyncio
class TestAsyncOrgScoped:
    async def test_set_uses_org_prefix(
        self, async_org_client: AsyncSirrClient, mock_api: respx.Router
    ):
        route = mock_api.post(f"/orgs/{ORG}/secrets").mock(
            return_value=httpx.Response(200, json={"key": "K"})
        )
        await async_org_client.set("K", "v")
        assert route.called

    async def test_get_uses_org_prefix(
        self, async_org_client: AsyncSirrClient, mock_api: respx.Router
    ):
        route = mock_api.get(f"/orgs/{ORG}/secrets/K").mock(
            return_value=httpx.Response(200, json={"key": "K", "value": "v"})
        )
        assert await async_org_client.get("K") == "v"
        assert route.called

    async def test_prune_uses_org_prefix(
        self, async_org_client: AsyncSirrClient, mock_api: respx.Router
    ):
        route = mock_api.post(f"/orgs/{ORG}/prune").mock(
            return_value=httpx.Response(200, json={"pruned": 0})
        )
        await async_org_client.prune()
        assert route.called

    async def test_audit_uses_org_prefix(
        self, async_org_client: AsyncSirrClient, mock_api: respx.Router
    ):
        route = mock_api.get(f"/orgs/{ORG}/audit").mock(
            return_value=httpx.Response(200, json={"events": []})
        )
        await async_org_client.get_audit_log()
        assert route.called

    async def test_patch_uses_org_prefix(
        self, async_org_client: AsyncSirrClient, mock_api: respx.Router
    ):
        meta = {"key": "K", "created_at": 1000, "read_count": 0}
        route = mock_api.patch(f"/orgs/{ORG}/secrets/K").mock(
            return_value=httpx.Response(200, json=meta)
        )
        await async_org_client.patch("K", reads=3)
        assert route.called


# ── Async public bucket tests ────────────────────────────────────────────


@pytest.mark.asyncio
class TestAsyncPublicBucket:
    async def test_push_no_org(self, async_public_client: AsyncSirrClient, mock_api: respx.Router):
        route = mock_api.post("/secrets").mock(
            return_value=httpx.Response(200, json={"id": "deadbeef" * 8})
        )
        await async_public_client.push("v")
        assert route.called

    async def test_get_no_org(self, async_public_client: AsyncSirrClient, mock_api: respx.Router):
        route = mock_api.get("/secrets/K").mock(
            return_value=httpx.Response(200, json={"key": "K", "value": "v"})
        )
        assert await async_public_client.get("K") == "v"
        assert route.called


# ── Async /me methods ───────────────────────────────────────────────────


@pytest.mark.asyncio
class TestAsyncMe:
    ME_RESP: ClassVar[dict] = {
        "id": "p_1",
        "name": "alice",
        "role": "reader",
        "org_id": "org_abc",
        "metadata": {},
        "keys": [],
    }

    async def test_me(self, async_public_client: AsyncSirrClient, mock_api: respx.Router):
        mock_api.get("/me").mock(return_value=httpx.Response(200, json=self.ME_RESP))
        info = await async_public_client.me()
        assert isinstance(info, MeInfo)
        assert info.id == "p_1"
        assert info.name == "alice"
        assert info.org_id == "org_abc"

    async def test_update_me(self, async_public_client: AsyncSirrClient, mock_api: respx.Router):
        updated = {**self.ME_RESP, "metadata": {"team": "eng"}}
        route = mock_api.patch("/me").mock(return_value=httpx.Response(200, json=updated))
        info = await async_public_client.update_me(metadata={"team": "eng"})
        assert info.metadata == {"team": "eng"}
        body = json.loads(route.calls[0].request.content)
        assert body["metadata"] == {"team": "eng"}

    async def test_create_key(self, async_public_client: AsyncSirrClient, mock_api: respx.Router):
        resp = {
            "id": "k_1",
            "name": "ci",
            "key": "sirr_key_abc",
            "valid_after": 1000,
            "valid_before": 32000000,
        }
        route = mock_api.post("/me/keys").mock(return_value=httpx.Response(201, json=resp))
        result = await async_public_client.create_key("ci")
        assert isinstance(result, ApiKeyCreateResult)
        assert result.key == "sirr_key_abc"
        body = json.loads(route.calls[0].request.content)
        assert body["name"] == "ci"

    async def test_delete_key(self, async_public_client: AsyncSirrClient, mock_api: respx.Router):
        mock_api.delete("/me/keys/k_1").mock(
            return_value=httpx.Response(200, json={"deleted": True})
        )
        assert await async_public_client.delete_key("k_1") is True


# ── Async admin methods ─────────────────────────────────────────────────


@pytest.mark.asyncio
class TestAsyncAdmin:
    async def test_create_org(self, async_public_client: AsyncSirrClient, mock_api: respx.Router):
        route = mock_api.post("/orgs").mock(
            return_value=httpx.Response(201, json={"id": ORG_ID, "name": "Acme"})
        )
        org = await async_public_client.create_org("Acme")
        assert isinstance(org, Org)
        assert org.name == "Acme"
        body = json.loads(route.calls[0].request.content)
        assert body["name"] == "Acme"

    async def test_list_orgs(self, async_public_client: AsyncSirrClient, mock_api: respx.Router):
        mock_api.get("/orgs").mock(
            return_value=httpx.Response(200, json={"orgs": [{"id": ORG_ID, "name": "Acme"}]})
        )
        orgs = await async_public_client.list_orgs()
        assert len(orgs) == 1

    async def test_delete_org(self, async_public_client: AsyncSirrClient, mock_api: respx.Router):
        mock_api.delete(f"/orgs/{ORG_ID}").mock(
            return_value=httpx.Response(200, json={"deleted": True})
        )
        assert await async_public_client.delete_org(ORG_ID) is True

    async def test_create_principal(
        self, async_public_client: AsyncSirrClient, mock_api: respx.Router
    ):
        route = mock_api.post(f"/orgs/{ORG_ID}/principals").mock(
            return_value=httpx.Response(
                201,
                json={"id": "pr_1", "name": "alice", "role": "reader", "org_id": ORG_ID},
            )
        )
        p = await async_public_client.create_principal(ORG_ID, "alice", "reader")
        assert isinstance(p, Principal)
        assert p.name == "alice"
        body = json.loads(route.calls[0].request.content)
        assert body["name"] == "alice"
        assert body["role"] == "reader"

    async def test_list_principals(
        self, async_public_client: AsyncSirrClient, mock_api: respx.Router
    ):
        mock_api.get(f"/orgs/{ORG_ID}/principals").mock(
            return_value=httpx.Response(
                200,
                json={
                    "principals": [
                        {"id": "pr_1", "name": "alice", "role": "reader", "org_id": ORG_ID}
                    ]
                },
            )
        )
        principals = await async_public_client.list_principals(ORG_ID)
        assert len(principals) == 1

    async def test_delete_principal(
        self, async_public_client: AsyncSirrClient, mock_api: respx.Router
    ):
        mock_api.delete(f"/orgs/{ORG_ID}/principals/pr_1").mock(
            return_value=httpx.Response(200, json={"deleted": True})
        )
        assert await async_public_client.delete_principal(ORG_ID, "pr_1") is True

    async def test_create_role(self, async_public_client: AsyncSirrClient, mock_api: respx.Router):
        route = mock_api.post(f"/orgs/{ORG_ID}/roles").mock(
            return_value=httpx.Response(
                201,
                json={"name": "editor", "permissions": "RW", "org_id": ORG_ID},
            )
        )
        role = await async_public_client.create_role(ORG_ID, "editor", permissions="RW")
        assert isinstance(role, Role)
        assert role.permissions == "RW"
        body = json.loads(route.calls[0].request.content)
        assert body["permissions"] == "RW"

    async def test_list_roles(self, async_public_client: AsyncSirrClient, mock_api: respx.Router):
        mock_api.get(f"/orgs/{ORG_ID}/roles").mock(
            return_value=httpx.Response(
                200,
                json={"roles": [{"name": "editor", "permissions": "RW", "org_id": ORG_ID}]},
            )
        )
        roles = await async_public_client.list_roles(ORG_ID)
        assert len(roles) == 1

    async def test_delete_role(self, async_public_client: AsyncSirrClient, mock_api: respx.Router):
        mock_api.delete(f"/orgs/{ORG_ID}/roles/editor").mock(
            return_value=httpx.Response(200, json={"deleted": True})
        )
        assert await async_public_client.delete_role(ORG_ID, "editor") is True
