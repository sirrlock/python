# python/tests/test_e2e_multitenant.py
# Multi-tenant E2E: two companies on one server, full isolation.
# NO license key — tests the real free-tier experience.
# Run with: SIRRD_BIN=/path/to/sirrd pytest tests/test_e2e_multitenant.py -v
from __future__ import annotations

import os
import shutil
import signal
import subprocess
import tempfile
import time

import httpx
import pytest

from sirr import SirrClient, SirrError

PORT = 39998
BASE = f"http://localhost:{PORT}"
MASTER_KEY = "python-mt-e2e-master-key"


@pytest.fixture(scope="module")
def sirrd():
    """Start an isolated sirrd server for the test module."""
    data_dir = tempfile.mkdtemp(prefix="sirr-e2e-py-")
    sirrd_bin = os.environ.get("SIRRD_BIN", shutil.which("sirrd") or "sirrd")
    proc = subprocess.Popen(
        [sirrd_bin, "serve", "--port", str(PORT)],
        env={
            **os.environ,
            "SIRR_MASTER_API_KEY": MASTER_KEY,
            "SIRR_DATA_DIR": data_dir,
            "SIRR_RATE_LIMIT_PER_SECOND": "1000",
            "SIRR_RATE_LIMIT_BURST": "1000",
        },
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    # Wait for health
    for _ in range(30):
        try:
            r = httpx.get(f"{BASE}/health", timeout=1)
            if r.is_success:
                break
        except Exception:
            pass
        time.sleep(0.3)
    else:
        proc.kill()
        raise RuntimeError("sirrd did not start in time")

    yield proc

    proc.send_signal(signal.SIGTERM)
    proc.wait(timeout=5)
    shutil.rmtree(data_dir, ignore_errors=True)


@pytest.fixture(scope="module")
def tenants(sirrd):
    """Create two orgs with principals and keys, return all handles."""
    master = SirrClient(server=BASE, token=MASTER_KEY)

    # ── Acme: org + 3 principals + keys ─────────────────────────────
    acme = master.create_org("acme")
    alice = master.create_principal(acme.id, "alice", "owner")
    bob = master.create_principal(acme.id, "bob", "writer")
    carol = master.create_principal(acme.id, "carol", "reader")

    alice_key = master.create_principal_key(acme.id, alice.id, "alice-key")
    bob_key = master.create_principal_key(acme.id, bob.id, "bob-key")
    carol_key = master.create_principal_key(acme.id, carol.id, "carol-key")

    # ── Globex: org + 2 principals + keys ───────────────────────────
    globex = master.create_org("globex")
    hank = master.create_principal(globex.id, "hank", "owner")
    marge = master.create_principal(globex.id, "marge", "writer")

    hank_key = master.create_principal_key(globex.id, hank.id, "hank-key")
    marge_key = master.create_principal_key(globex.id, marge.id, "marge-key")

    result = {
        "master": master,
        "acme_id": acme.id,
        "globex_id": globex.id,
        "alice_key": alice_key.key,
        "bob_key": bob_key.key,
        "carol_key": carol_key.key,
        "hank_key": hank_key.key,
        "marge_key": marge_key.key,
    }
    yield result
    master.close()


# ── Helpers ──────────────────────────────────────────────────────────────────


def acme_as(tenants: dict, token: str) -> SirrClient:
    return SirrClient(server=BASE, token=token, org=tenants["acme_id"])


def globex_as(tenants: dict, token: str) -> SirrClient:
    return SirrClient(server=BASE, token=token, org=tenants["globex_id"])


# ── Tests ────────────────────────────────────────────────────────────────────


class TestSetup:
    def test_server_healthy(self, tenants):
        assert tenants["master"].health() is True

    def test_two_orgs_created(self, tenants):
        orgs = tenants["master"].list_orgs()
        names = [o.name for o in orgs]
        assert "acme" in names
        assert "globex" in names


class TestAuthentication:
    def test_alice_authenticates(self, tenants):
        with acme_as(tenants, tenants["alice_key"]) as c:
            me = c.me()
            assert me.name == "alice"
            assert me.role == "owner"

    def test_bob_authenticates(self, tenants):
        with acme_as(tenants, tenants["bob_key"]) as c:
            me = c.me()
            assert me.name == "bob"
            assert me.role == "writer"

    def test_hank_authenticates(self, tenants):
        with globex_as(tenants, tenants["hank_key"]) as c:
            me = c.me()
            assert me.name == "hank"
            assert me.role == "owner"


class TestAcmeSecrets:
    def test_alice_owner_set_and_read(self, tenants):
        with acme_as(tenants, tenants["alice_key"]) as c:
            c.set("DB_URL", "postgres://acme-db:5432/acme", reads=10)
            assert c.get("DB_URL") == "postgres://acme-db:5432/acme"

    def test_bob_writer_set_and_read(self, tenants):
        with acme_as(tenants, tenants["bob_key"]) as c:
            c.set("API_KEY", "acme-api-key-42", reads=10)
            assert c.get("API_KEY") == "acme-api-key-42"

    def test_carol_reader_cannot_create(self, tenants):
        with acme_as(tenants, tenants["carol_key"]) as c:
            with pytest.raises(SirrError) as exc:
                c.set("NOPE", "denied")
            assert exc.value.status == 403


class TestGlobexSecrets:
    def test_hank_sets_db_url_same_key_name(self, tenants):
        with globex_as(tenants, tenants["hank_key"]) as c:
            c.set("DB_URL", "postgres://globex-db:5432/globex", reads=10)
            assert c.get("DB_URL") == "postgres://globex-db:5432/globex"

    def test_marge_writer_set_and_read(self, tenants):
        with globex_as(tenants, tenants["marge_key"]) as c:
            c.set("STRIPE_KEY", "sk_test_globex", reads=10)
            assert c.get("STRIPE_KEY") == "sk_test_globex"


class TestOrgIsolationSameKeyName:
    def test_acme_db_url_still_acme(self, tenants):
        with acme_as(tenants, tenants["alice_key"]) as c:
            assert c.get("DB_URL") == "postgres://acme-db:5432/acme"

    def test_globex_db_url_still_globex(self, tenants):
        with globex_as(tenants, tenants["hank_key"]) as c:
            assert c.get("DB_URL") == "postgres://globex-db:5432/globex"


class TestCrossOrgIsolation:
    def test_hank_cannot_read_acme(self, tenants):
        with acme_as(tenants, tenants["hank_key"]) as c:
            with pytest.raises(SirrError):
                c.get("DB_URL")

    def test_alice_cannot_read_globex(self, tenants):
        with globex_as(tenants, tenants["alice_key"]) as c:
            with pytest.raises(SirrError):
                c.get("DB_URL")

    def test_marge_cannot_write_acme(self, tenants):
        with acme_as(tenants, tenants["marge_key"]) as c:
            with pytest.raises(SirrError):
                c.set("HACK", "nope")

    def test_bob_cannot_write_globex(self, tenants):
        with globex_as(tenants, tenants["bob_key"]) as c:
            with pytest.raises(SirrError):
                c.set("HACK", "nope")


class TestPublicDeadDrop:
    def test_push_and_get_without_org(self, tenants):
        # Use raw httpx — SirrClient requires a token but public dead drops don't
        resp = httpx.post(f"{BASE}/secrets", json={"value": "hello-from-python"})
        assert resp.status_code in (200, 201)
        secret_id = resp.json()["id"]
        assert secret_id

        resp2 = httpx.get(f"{BASE}/secrets/{secret_id}")
        assert resp2.status_code == 200
        assert resp2.json()["value"] == "hello-from-python"


class TestBurnAfterRead:
    def test_first_read_returns_second_returns_none(self, tenants):
        with acme_as(tenants, tenants["alice_key"]) as c:
            c.set("BURN_PY", "burnme", reads=1)
            assert c.get("BURN_PY") == "burnme"
            assert c.get("BURN_PY") is None


class TestSelfServiceKey:
    def test_alice_creates_own_key(self, tenants):
        with acme_as(tenants, tenants["alice_key"]) as c:
            new_key = c.create_key("alice-self-key")
            assert new_key.key

        with acme_as(tenants, new_key.key) as c2:
            me = c2.me()
            assert me.name == "alice"
