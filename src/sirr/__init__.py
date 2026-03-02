"""sirr — Python client for the Sirr ephemeral secret vault."""

from sirr._async_client import AsyncSirrClient
from sirr._client import SirrClient
from sirr._exceptions import SirrError
from sirr._models import (
    ApiKey,
    ApiKeyCreateResult,
    AuditEvent,
    SecretMeta,
    Webhook,
    WebhookCreateResult,
)

__all__ = [
    "ApiKey",
    "ApiKeyCreateResult",
    "AsyncSirrClient",
    "AuditEvent",
    "SecretMeta",
    "SirrClient",
    "SirrError",
    "Webhook",
    "WebhookCreateResult",
]
