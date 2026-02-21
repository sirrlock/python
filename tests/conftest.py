from __future__ import annotations

import pytest
import respx

from sirr import AsyncSirrClient, SirrClient

SERVER = "https://vault.example.com"
TOKEN = "test-token-abc"


@pytest.fixture()
def mock_api():
    with respx.mock(base_url=SERVER) as router:
        yield router


@pytest.fixture()
def client(mock_api):
    with SirrClient(server=SERVER, token=TOKEN) as c:
        yield c


@pytest.fixture()
async def async_client(mock_api):
    async with AsyncSirrClient(server=SERVER, token=TOKEN) as c:
        yield c
