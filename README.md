# sirr (Python)

[![PyPI](https://img.shields.io/pypi/v/sirr)](https://pypi.org/project/sirr/)
[![PyPI downloads](https://img.shields.io/pypi/dm/sirr)](https://pypi.org/project/sirr/)
[![CI](https://github.com/sirrlock/python/actions/workflows/ci.yml/badge.svg)](https://github.com/sirrlock/python/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/python-%3E%3D3.10-blue)](https://www.python.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![GitHub stars](https://img.shields.io/github/stars/sirrlock/python)](https://github.com/sirrlock/python)
[![Last commit](https://img.shields.io/github/last-commit/sirrlock/python)](https://github.com/sirrlock/python)

**Ephemeral secrets for Python AI agents. Credentials that delete themselves.**

`sirr` is the Python client for [Sirr](https://github.com/sirrlock/sirr) — a self-hosted vault where every secret expires by read count, by time, or both. Built for the Python AI ecosystem: LangChain, CrewAI, AutoGen, LlamaIndex, and any framework that needs to hand credentials to agents without leaving them lying around forever.

---

## The Problem It Solves

Python dominates the AI/ML landscape. That means Python is where credentials get handed to agents, embedded in tool calls, interpolated into prompts, and logged by frameworks. Every time an agent reads a database URL or API key, you have limited visibility into what that framework stored, logged, or will use for fine-tuning.

The standard answer — "rotate your secrets after every session" — doesn't scale. You forget. It's tedious. It requires manual IAM work.

Sirr gives you a better primitive: **credentials that enforce their own expiry.** An agent reads it once. The server deletes it. You don't have to remember to clean anything up.

```python
# Give a CrewAI agent exactly one read of your API key
sirr.push("OPENAI_KEY", api_key, reads=1, ttl=600)

# Agent calls sirr.get("OPENAI_KEY") → gets the value → record deleted
# Even if CrewAI logs the value to its trace file, it's already dead on your server
```

---

## Install

```bash
pip install sirr
```

Requires Python 3.10+. Supports sync and async.

---

## Usage

```python
import os
from sirr import SirrClient

sirr = SirrClient(
    server=os.environ.get("SIRR_SERVER", "http://localhost:39999"),
    token=os.environ["SIRR_TOKEN"],
)

# Push a one-time secret
sirr.push("API_KEY", "sk-...", reads=1, ttl=3600)

# Retrieve — None if burned or expired
value = sirr.get("API_KEY")

# Inspect metadata without consuming a read
meta = sirr.head("API_KEY")
# → SecretHead(key='API_KEY', read_count=0, reads_remaining=1, ...)

# Pull all secrets into a dict
secrets = sirr.pull_all()
# → {"API_KEY": "sk-...", "DB_URL": "postgres://..."}

# Inject as environment variables for the duration of a block
with sirr.env():
    # os.environ["API_KEY"] is set here
    run_agent_task()
    # restored on exit, even on exception

# Update an existing secret in place
sirr.patch("API_KEY", value="sk-new...", ttl=600)

# Delete immediately
sirr.delete("API_KEY")

# List active secrets (metadata only — no values)
entries = sirr.list()

# Prune expired secrets
pruned = sirr.prune()

# Check server health
alive = sirr.health()  # True / False
```

### Sealed Secrets

A secret with `reads=N, delete=False` is sealed once the read limit is exhausted — it stays on
the server but can no longer be read. `get()` and `patch()` will raise `SirrSealed` (a subclass
of `SirrError`) in this case. Use `head()` to inspect a sealed secret without triggering an error:

```python
from sirr import SirrSealed

sirr.push("AUDIT_KEY", value, reads=3, delete=False)

try:
    value = sirr.get("AUDIT_KEY")
except SirrSealed:
    meta = sirr.head("AUDIT_KEY")
    print(f"sealed — read {meta.read_count} times, created at {meta.created_at}")
```

### Async

```python
from sirr import AsyncSirrClient

async with AsyncSirrClient(server=..., token=...) as sirr:
    await sirr.push("API_KEY", "sk-...", reads=1, ttl=3600)
    value = await sirr.get("API_KEY")
    meta = await sirr.head("API_KEY")
```

---

## AI Workflows

### LangChain tool with scoped credential

```python
from langchain.tools import tool

@tool
def query_production_db(sql: str) -> str:
    """Run a SQL query against the production database."""
    conn_str = sirr.get("AGENT_DB")
    if conn_str is None:
        raise ValueError("DB credential expired or already used")
    return run_query(conn_str, sql)
```

### CrewAI agent with burn-after-use credential

```python
from crewai import Agent, Task, Crew

# Push before the crew runs — burns after first read
sirr.push("STRIPE_KEY", stripe_key, reads=1, ttl=600)

analyst = Agent(
    role="Data Analyst",
    goal="Fetch and analyze payment data",
    tools=[stripe_tool],  # tool calls sirr.get("STRIPE_KEY") internally
)

crew = Crew(agents=[analyst], tasks=[analysis_task])
crew.kickoff()
# STRIPE_KEY was read once by the tool — already deleted
```

### AutoGen multi-agent with isolated credentials

```python
import autogen

# Each agent gets its own scoped, expiring credential
sirr.push("AGENT_1_DB", db_url_1, reads=5, ttl=3600)
sirr.push("AGENT_2_DB", db_url_2, reads=5, ttl=3600)

# Agents run — their credential budgets are enforced server-side
# No agent can exceed its read limit even if the framework retries
```

### Inject all secrets into a subprocess

```python
with sirr.env():
    # All Sirr secrets set as os.environ
    subprocess.run(["python", "agent_script.py"])
# Env restored after block
```

### pytest fixture for CI secrets

```python
import pytest
from sirr import SirrClient

@pytest.fixture(autouse=True)
def inject_test_secrets():
    sirr = SirrClient(server=os.environ["SIRR_SERVER"], token=os.environ["SIRR_TOKEN"])
    with sirr.env():
        yield
    # Credentials cleaned from env after each test
```

---

## Multi-Tenant / Org Mode

When running against a multi-tenant Sirr server, pass the `org` parameter to scope
all secret, audit, webhook, and prune operations to that organization:

```python
from sirr import SirrClient

sirr = SirrClient(
    server="https://vault.example.com",
    token=os.environ["SIRR_TOKEN"],
    org="acme",
)

# All calls now hit /orgs/acme/secrets, /orgs/acme/audit, etc.
sirr.push("DB_URL", "postgres://...", reads=3)
entries = sirr.list()
events = sirr.get_audit_log()
```

Without `org`, URLs remain unchanged (`/secrets`, `/audit`, etc.) — fully backward-compatible.

### /me endpoints

Inspect or update the currently authenticated principal:

```python
info = sirr.me()                          # GET /me → MeInfo
sirr.update_me(metadata={"env": "prod"}) # PATCH /me → MeInfo
key = sirr.create_key("ci")              # POST /me/keys → ApiKeyCreateResult
print(key.key)                            # sirr_key_... (shown once)
sirr.delete_key(key.id)                  # DELETE /me/keys/:id
```

### Admin endpoints

Manage orgs, principals, and roles (requires admin privileges):

```python
# Orgs
org = sirr.create_org("Acme", metadata={"env": "prod"})
orgs = sirr.list_orgs()
sirr.delete_org(org.id)

# Principals
p = sirr.create_principal(org.id, "alice", "writer")
principals = sirr.list_principals(org.id)
sirr.delete_principal(org.id, p.id)

# Roles
role = sirr.create_role(org.id, "writer", permissions="rRlL")
roles = sirr.list_roles(org.id)
sirr.delete_role(org.id, role.name)
```

Permission strings use single letters: `r` read-own, `R` read-any, `w` write-own, `W` write-any,
`l` list-own, `L` list-any, `d` delete-own, `D` delete-any, `m` manage.

### Async

All multi-tenant, `/me`, and admin methods are also available on `AsyncSirrClient`:

```python
from sirr import AsyncSirrClient

async with AsyncSirrClient(server=..., token=..., org="acme") as sirr:
    await sirr.push("KEY", "value")
    info = await sirr.me()
    org = await sirr.create_org("NewOrg")
    p = await sirr.create_principal(org.id, "bob", "reader")
```

---

## Related

| Package | Description |
|---------|-------------|
| [sirr](https://github.com/sirrlock/sirr) | Rust monorepo: `sirrd` server + `sirr` CLI |
| [@sirrlock/mcp](https://github.com/sirrlock/mcp) | MCP server for AI assistants |
| [@sirrlock/node](https://github.com/sirrlock/node) | Node.js / TypeScript SDK |
| [Sirr.Client (NuGet)](https://github.com/sirrlock/dotnet) | .NET SDK |
| [sirr.dev](https://sirr.dev) | Documentation |
| [sirrlock.com](https://sirrlock.com) | Managed cloud + license keys |
