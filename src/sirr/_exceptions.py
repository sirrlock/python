from __future__ import annotations


class SirrError(Exception):
    """Raised when the Sirr API returns a non-2xx response."""

    def __init__(self, status: int, message: str) -> None:
        self.status = status
        self.message = message
        super().__init__(f"Sirr API error {status}: {message}")


class SirrSealed(SirrError):
    """Raised when a secret is sealed (read limit exhausted, delete=false).

    A sealed secret still exists on the server but can no longer be read.
    Use ``client.head(key)`` to inspect its metadata without consuming a read.
    """

    def __init__(self, message: str = "secret is sealed — reads exhausted") -> None:
        super().__init__(410, message)


class SecretExistsError(SirrError):
    """Raised when a org secret key already exists (HTTP 409 Conflict).

    The server returns this when ``POST /orgs/{org}/secrets`` is called with a
    key that is already stored.  Either delete the existing secret first or use
    a different key.
    """

    def __init__(self, message: str = "secret already exists") -> None:
        super().__init__(409, message)
