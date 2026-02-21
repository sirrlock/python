from __future__ import annotations

from typing import Any

import httpx

from sirr._exceptions import SirrError


def build_headers(token: str) -> dict[str, str]:
    return {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }


def normalize_server(server: str) -> str:
    return server.rstrip("/")


def handle_response(response: httpx.Response, *, allow_404: bool = False) -> Any:
    """Parse a Sirr API response, raising SirrError on non-2xx (unless 404 is allowed)."""
    if allow_404 and response.status_code == 404:
        return None
    if not response.is_success:
        try:
            body = response.json()
            message = body.get("error", response.text)
        except Exception:
            message = response.text
        raise SirrError(response.status_code, message)
    return response.json()
