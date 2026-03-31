"""sirr — Python client for the Sirr ephemeral secret vault."""

from sirr._async_client import AsyncSirrClient
from sirr._client import SirrClient
from sirr._exceptions import SecretExistsError, SirrError, SirrSealed
from sirr._models import (
    ApiKeyCreateResult,
    AuditEvent,
    MeInfo,
    Org,
    Principal,
    Role,
    SecretHead,
    SecretMeta,
    Webhook,
    WebhookCreateResult,
)

__all__ = [
    "ApiKeyCreateResult",
    "AsyncSirrClient",
    "AuditEvent",
    "MeInfo",
    "Org",
    "Principal",
    "Role",
    "SecretExistsError",
    "SecretHead",
    "SecretMeta",
    "SirrClient",
    "SirrError",
    "SirrSealed",
    "Webhook",
    "WebhookCreateResult",
]
