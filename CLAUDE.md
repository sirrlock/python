# sirr Python Client — Claude Development Guide

## Purpose

Python HTTP client for the Sirr API. Published to PyPI as `sirr`.
Supports both sync and async usage.

## Architecture

```
src/sirr/
├── __init__.py          # Re-exports: SirrClient, AsyncSirrClient, SecretMeta, SirrError
├── _exceptions.py       # SirrError(status, message)
├── _models.py           # SecretMeta frozen dataclass with from_dict()
├── _transport.py        # Shared: build_headers, normalize_server, handle_response
├── _client.py           # SirrClient (sync, httpx.Client)
├── _async_client.py     # AsyncSirrClient (async, httpx.AsyncClient)
└── py.typed             # PEP 561 marker
```

**DRY strategy**: `_transport.py` handles headers, URL normalization, and response parsing.
Both clients call into it. No base class — the duplication across 6 methods is minimal.

## API Surface

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
    def env(self) -> ContextManager                # injects into os.environ

class AsyncSirrClient:
    # Same surface but all methods are async
    # pull_all() uses asyncio.gather for concurrent fetches
    # env() is an @asynccontextmanager
```

## Stack

- Python 3.10+
- `httpx` for HTTP (supports both sync and async)
- `pytest` + `pytest-asyncio` + `respx` for tests
- `ruff` for linting and formatting
- `hatchling` build backend
- Published via `pyproject.toml` (no setup.py)

## Key Rules

- `get()` returns `None` on 404 — do not raise
- All other non-2xx responses raise `SirrError`
- Never log secret values
- `env()` context manager must restore original env on exit (even on exception)
- Keys are URL-encoded in paths (`urllib.parse.quote(key, safe='')`)

## Commands

```bash
# Install (editable + dev deps)
pip install -e ".[dev]"

# Lint
ruff check src/ tests/
ruff format --check src/ tests/

# Test
pytest --cov=sirr --cov-report=term-missing

# Build
python -m build
```

## Pre-Commit Checklist

Before every commit and push, review and update if needed:

1. **README.md** — Does it reflect new methods or behavior?
2. **CLAUDE.md** — New constraints or API decisions worth recording?
