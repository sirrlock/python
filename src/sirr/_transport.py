from __future__ import annotations

from typing import Any

import httpx

from sirr._exceptions import SirrError


def build_headers(token: str | None = None) -> dict[str, str]:
    headers = {
        "Content-Type": "application/json",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def normalize_server(server: str) -> str:
    return server.rstrip("/")


def handle_response(response: httpx.Response, *, allow_410: bool = False) -> Any:
    """Parse a Sirr API response, raising SirrError on non-2xx.

    - 410 is returned as None when allow_410=True (useful for get()).
    """
    if allow_410 and response.status_code == 410:
        return None

    if not response.is_success:
        message = "unknown error"
        try:
            body = response.json()
            message = body.get("error", response.text)
        except Exception:
            message = response.text or str(response.status_code)
        raise SirrError(response.status_code, message)

    if response.status_code == 204:
        return None

    return response.json()
