from __future__ import annotations


class SirrError(Exception):
    """Raised when the Sirr API returns a non-2xx response."""

    def __init__(self, status: int, message: str) -> None:
        self.status = status
        self.message = message
        super().__init__(f"Sirr API error {status}: {message}")
