from __future__ import annotations
import httpx
import pytest
import respx
import re
from sirr import SirrClient

def test_full_flow_simulation():
    """Simulate the full lifecycle of a secret as seen in e2e.sh."""
    
    # We use a stateful mock to simulate the server
    secrets = {}
    
    def push_mock(request):
        import json
        body = json.loads(request.content)
        # simplified hash generation for mock
        val = body["value"]
        h = f"hash_{val}"
        secrets[h] = {"value": val, "reads": body.get("reads", 1), "burned": False}
        return httpx.Response(201, json={"hash": h, "url": f"http://test/s/{h}", "owned": True})

    def get_mock(request):
        # respx doesn't pass named groups to side_effect easily, we parse from URL
        match = re.search(r"/secret/([^/]+)", str(request.url))
        if not match:
            return httpx.Response(404)
        h = match.group(1)
        if h not in secrets or secrets[h]["burned"]:
            return httpx.Response(410)
        
        val = secrets[h]["value"]
        secrets[h]["reads"] -= 1
        if secrets[h]["reads"] <= 0:
            secrets[h]["burned"] = True
        return httpx.Response(200, content=val)

    with respx.mock(base_url="https://vault.test") as respx_mock:
        respx_mock.post("/secret").mock(side_effect=push_mock)
        respx_mock.get(url__regex=r"/secret/\w+").mock(side_effect=get_mock)
        respx_mock.delete(url__regex=r"/secret/\w+").mock(return_value=httpx.Response(204))
        
        with SirrClient(server="https://vault.test", token="tok") as client:
            # 1. Push
            res = client.push("hello", reads=2)
            h = res.hash
            assert h == "hash_hello"
            
            # 2. Get first time
            assert client.get(h) == "hello"
            
            # 3. Get second time (should burn after this)
            assert client.get(h) == "hello"
            
            # 4. Get third time (should be 410 -> None)
            assert client.get(h) is None
            
            # 5. Push another and burn manually
            res2 = client.push("burn-me")
            h2 = res2.hash
            client.burn(h2)
            # simulate burn in our state
            secrets[h2]["burned"] = True
            assert client.get(h2) is None
