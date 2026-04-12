from __future__ import annotations


class SirrError(Exception):
    """Base exception for all Sirr API errors."""

    def __init__(self, status: int, message: str) -> None:
        self.status = status
        self.message = message
        super().__init__(f"Sirr API error {status}: {message}")
