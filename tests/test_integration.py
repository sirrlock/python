# python/tests/test_integration.py
# Real integration tests against a live sirrd process.
# Starts sirrd on port 39996; requires sirrd on PATH.
# Run with: SIRR_INTEGRATION=1 .venv/bin/pytest tests/test_integration.py -v
import os
import shutil
import subprocess
import tempfile
import time

import httpx
import pytest

from sirr import SirrClient

pytestmark = pytest.mark.skipif(
    not os.environ.get("SIRR_INTEGRATION"),
    reason="Set SIRR_INTEGRATION=1 to run against real sirrd",
)

PORT = 39996
BASE = f"http://localhost:{PORT}"
MASTER_KEY = "python-integration-test-key"
LICENSE_KEY = "sirr_lic_0000000000000000000000000000000000000000"


def wait_for_health(retries: int = 30) -> None:
    for _ in range(retries):
        try:
            r = httpx.get(f"{BASE}/health", timeout=1)
            if r.is_success:
                return
        except Exception:
            pass
        time.sleep(0.2)
    raise RuntimeError("sirrd did not start in time")


def parse_bootstrap_output(output: str) -> tuple[str, str]:
    """Parse org_id and first bootstrap key from sirrd auto-init output."""
    import re

    org_match = re.search(r"org_id:\s+([0-9a-f]{32})", output)
    key_match = re.search(r"key=(sirr_key_[0-9a-f]+)", output)
    if not org_match or not key_match:
        raise RuntimeError(f"Failed to parse bootstrap info from output:\n{output}")
    return org_match.group(1), key_match.group(1)


@pytest.fixture(scope="session")
def sirrd_server():
    tmpdir = tempfile.mkdtemp()
    proc = subprocess.Popen(
        ["sirrd", "serve", "--port", str(PORT)],
        env={
            **os.environ,
            "SIRR_API_KEY": MASTER_KEY,
            "SIRR_LICENSE_KEY": LICENSE_KEY,
            "SIRR_AUTOINIT": "1",
            "SIRR_DATA_DIR": tmpdir,
        },
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    wait_for_health()
    # Give sirrd a moment to flush auto-init output
    time.sleep(0.3)
    yield proc
    proc.kill()
    shutil.rmtree(tmpdir, ignore_errors=True)


@pytest.fixture(scope="session")
def bootstrap(sirrd_server) -> tuple[str, str]:
    """Returns (org_id, bootstrap_key) from the auto-init output."""
    # Collect available output (non-blocking after server is up)
    import select

    output_chunks = []
    for stream in [sirrd_server.stdout, sirrd_server.stderr]:
        if stream:
            # Read available data without blocking
            while True:
                try:
                    ready = select.select([stream], [], [], 0.1)[0]
                    if not ready:
                        break
                    chunk = stream.read1(4096) if hasattr(stream, "read1") else stream.read(4096)
                    if not chunk:
                        break
                    output_chunks.append(chunk.decode("utf-8", errors="replace"))
                except Exception:
                    break
    output = "".join(output_chunks)
    return parse_bootstrap_output(output)


@pytest.fixture(scope="session")
def org_id(bootstrap) -> str:
    return bootstrap[0]


@pytest.fixture(scope="session")
def bootstrap_key(bootstrap) -> str:
    return bootstrap[1]


@pytest.fixture(scope="session")
def org_principals_created(org_id):
    """Create alice + bob principals in the bootstrapped org (master key)."""
    # Create alice (writer) and bob (reader)
    # Note: no keys issued — POST /me/keys is self-service only (master key returns 403)
    httpx.post(
        f"{BASE}/orgs/{org_id}/principals",
        headers={"Authorization": f"Bearer {MASTER_KEY}"},
        json={"name": "alice", "role": "writer"},
    ).raise_for_status()
    httpx.post(
        f"{BASE}/orgs/{org_id}/principals",
        headers={"Authorization": f"Bearer {MASTER_KEY}"},
        json={"name": "bob", "role": "reader"},
    ).raise_for_status()
    return True


def test_health(sirrd_server):
    r = httpx.get(f"{BASE}/health")
    assert r.json()["status"] == "ok"


def test_public_secret(sirrd_server):
    admin = SirrClient(server=BASE, token=MASTER_KEY)
    result = admin.push("hello-public", ttl=3600)
    secret_id = result["id"]
    assert admin.get(secret_id) == "hello-public"


def test_org_principals_created(org_principals_created):
    assert org_principals_created is True


def test_org_secret_bootstrap_key_can_read(org_id, bootstrap_key):
    # bootstrap_key is the auto-init admin principal key (tied to org_id)
    admin = SirrClient(server=BASE, token=bootstrap_key, org=org_id)
    admin.set("PY_PRIVATE", "secret123", ttl=3600, reads=10)
    assert admin.get("PY_PRIVATE") == "secret123"


def test_org_secret_no_auth_returns_401(org_id):
    r = httpx.get(f"{BASE}/orgs/{org_id}/secrets/PY_PRIVATE")
    assert r.status_code == 401


def test_org_secret_wrong_key_returns_401(org_id):
    r = httpx.get(
        f"{BASE}/orgs/{org_id}/secrets/PY_PRIVATE",
        headers={"Authorization": "Bearer definitely-wrong-key"},
    )
    assert r.status_code == 401


def test_burn_after_read(org_id, bootstrap_key):
    admin = SirrClient(server=BASE, token=bootstrap_key, org=org_id)
    admin.set("PY_BURN", "burnme", ttl=3600, reads=1)
    assert admin.get("PY_BURN") == "burnme"
    assert admin.get("PY_BURN") is None  # burned


def test_head_does_not_consume_read(org_id, bootstrap_key):
    admin = SirrClient(server=BASE, token=bootstrap_key, org=org_id)
    admin.set("PY_HEAD", "headval", ttl=3600, reads=3)
    before = admin.head("PY_HEAD")
    assert before is not None
    assert before.read_count == 0
    assert before.reads_remaining == 3
    # head again — still not consumed
    again = admin.head("PY_HEAD")
    assert again.read_count == 0
    # now actually read
    assert admin.get("PY_HEAD") == "headval"
    after = admin.head("PY_HEAD")
    assert after.read_count == 1
    assert after.reads_remaining == 2


def test_seal_on_expiry_and_patch(org_id, bootstrap_key):
    from sirr import SirrSealed

    admin = SirrClient(server=BASE, token=bootstrap_key, org=org_id)
    admin.push("PY_SEAL", "sealme", ttl=3600, reads=1, delete=False)
    assert admin.get("PY_SEAL") == "sealme"
    # reads exhausted — secret sealed, not deleted
    with pytest.raises(SirrSealed):
        admin.get("PY_SEAL")
    # head still works on a sealed secret
    meta = admin.head("PY_SEAL")
    assert meta is not None
    assert meta.sealed is True
    # patch on sealed secret should raise
    with pytest.raises(SirrSealed):
        admin.patch("PY_SEAL", ttl=7200)


def test_org_lifecycle(sirrd_server):
    admin = SirrClient(server=BASE, token=MASTER_KEY)
    org = None
    try:
        org = admin.create_org("py-test-org")
        assert org.name == "py-test-org"
        orgs = admin.list_orgs()
        assert any(o.id == org.id for o in orgs)
    finally:
        if org:
            admin.delete_org(org.id)
    orgs_after = admin.list_orgs()
    assert not any(o.id == org.id for o in orgs_after)


def test_principal_lifecycle(sirrd_server):
    admin = SirrClient(server=BASE, token=MASTER_KEY)
    org = None
    try:
        org = admin.create_org("py-principal-lifecycle-org")
        role = admin.create_role(org.id, "py-writer", permissions="rRwWlL")
        principal = admin.create_principal(org.id, "py-alice", role.name)
        assert principal.name == "py-alice"
        principals = admin.list_principals(org.id)
        assert any(p.id == principal.id for p in principals)
        admin.delete_principal(org.id, principal.id)
        principals_after = admin.list_principals(org.id)
        assert not any(p.id == principal.id for p in principals_after)
        admin.delete_role(org.id, role.name)
    finally:
        if org:
            admin.delete_org(org.id)
