# sirr Python Client — Claude Development Guide

## Purpose

Python HTTP client for the Sirr API. Published to PyPI as `sirr`.
Supports both sync and async usage.

## Planned API Surface

```python
class SirrClient:
    def __init__(self, server: str, token: str): ...

    # Sync
    def push(self, key: str, value: str, *, ttl: int | None = None, reads: int | None = None) -> None
    def get(self, key: str) -> str | None          # None if burned/expired
    def delete(self, key: str) -> None
    def list(self) -> list[SecretMeta]
    def pull_all(self) -> dict[str, str]
    def prune(self) -> int
    def env(self) -> ContextManager                # context manager: injects into os.environ

class AsyncSirrClient:
    # Same surface but all methods are async
```

## Stack

- Python 3.10+
- `httpx` for HTTP (supports both sync and async)
- `pytest` + `respx` for tests
- Published via `pyproject.toml` (no setup.py)

## Key Rules

- `get()` returns `None` on 404 — do not raise
- All other non-2xx responses raise `SirrError`
- Never log secret values
- `env()` context manager must restore original env on exit (even on exception)

## Pre-Commit Checklist

Before every commit and push, review and update if needed:

1. **README.md** — Does it reflect new methods or behavior?
2. **CLAUDE.md** — New constraints or API decisions worth recording?
