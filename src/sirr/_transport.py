from __future__ import annotations

from typing import Any

import httpx

from sirr._exceptions import SirrError, SirrSealed


def build_headers(token: str) -> dict[str, str]:
    return {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }


def normalize_server(server: str) -> str:
    return server.rstrip("/")


def secrets_prefix(base: str, org: str | None) -> str:
    return f"{base}/orgs/{org}/secrets" if org else f"{base}/secrets"


def audit_prefix(base: str, org: str | None) -> str:
    return f"{base}/orgs/{org}/audit" if org else f"{base}/audit"


def webhooks_prefix(base: str, org: str | None) -> str:
    return f"{base}/orgs/{org}/webhooks" if org else f"{base}/webhooks"


def prune_prefix(base: str, org: str | None) -> str:
    return f"{base}/orgs/{org}/prune" if org else f"{base}/prune"


def handle_response(response: httpx.Response, *, allow_404: bool = False) -> Any:
    """Parse a Sirr API response, raising SirrError on non-2xx.

    - 404 is silently returned as None when allow_404=True.
    - 410 always raises SirrSealed (secret exists but reads are exhausted).
    """
    if allow_404 and response.status_code == 404:
        return None
    if response.status_code == 410:
        try:
            message = response.json().get("error", response.text)
        except Exception:
            message = response.text
        raise SirrSealed(message)
    if not response.is_success:
        try:
            body = response.json()
            message = body.get("error", response.text)
        except Exception:
            message = response.text
        raise SirrError(response.status_code, message)
    return response.json()
