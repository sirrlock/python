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
# Push a dead drop — returns a one-time URL
result = sirr.push(api_key, reads=1, ttl=600)
print(result.url)  # → https://sirrlock.com/s/abc123

# Or set an org-scoped named secret
sirr.set("OPENAI_KEY", api_key, org="acme", reads=1, ttl=600)
# Agent calls sirr.get("OPENAI_KEY", org="acme") → gets the value → record deleted
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
from sirr import SirrClient, SecretExistsError

sirr = SirrClient(
    server=os.environ.get("SIRR_SERVER", "https://sirrlock.com"),
    token=os.environ["SIRR_TOKEN"],
)

# Push a public dead drop — returns { id, url }
result = sirr.push("sk-...", reads=1, ttl=3600)
print(result.url)  # → https://sirrlock.com/s/abc123

# Set an org-scoped named secret — raises SecretExistsError on 409
sirr.set("DB_URL", "postgres://...", org="acme", ttl=86400, reads=3)

# Retrieve — routes by org presence
value = sirr.get(result.id)                     # dead drop by ID
db_url = sirr.get("DB_URL", org="acme")         # org-scoped by key

# Handle conflicts
try:
    sirr.set("DB_URL", "postgres://new...", org="acme")
except SecretExistsError:
    print("Key already exists — delete first or use a different key")

# Inspect metadata without consuming a read
meta = sirr.head("DB_URL")
# → SecretHead(key='DB_URL', read_count=0, reads_remaining=3, ...)

# Pull all secrets into a dict
secrets = sirr.pull_all()
# → {"DB_URL": "postgres://..."}

# Inject as environment variables for the duration of a block
with sirr.env():
    # os.environ["DB_URL"] is set here
    run_agent_task()
    # restored on exit, even on exception

# Delete immediately
sirr.delete("DB_URL")

# List active secrets (metadata only — no values)
entries = sirr.list()

# Prune expired secrets
pruned = sirr.prune()

# Check server health
alive = sirr.health()  # True / False
```

### Sealed Secrets

A secret with `reads=N, delete=False` is sealed once the read limit is exhausted — it stays on
the server but can no longer be read. `get()` will raise `SirrSealed` (a subclass
of `SirrError`) in this case. Use `head()` to inspect a sealed secret without triggering an error:

```python
from sirr import SirrSealed

sirr.set("AUDIT_KEY", value, org="acme", reads=3, delete=False)

try:
    value = sirr.get("AUDIT_KEY", org="acme")
except SirrSealed:
    meta = sirr.head("AUDIT_KEY")
    print(f"sealed — read {meta.read_count} times, created at {meta.created_at}")
```

### Async

```python
from sirr import AsyncSirrClient, SecretExistsError

async with AsyncSirrClient(server=..., token=...) as sirr:
    # Push a dead drop
    result = await sirr.push("sk-...", reads=1, ttl=3600)
    value = await sirr.get(result.id)

    # Set an org-scoped secret
    await sirr.set("API_KEY", "sk-...", org="acme", reads=1)
    value = await sirr.get("API_KEY", org="acme")
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

# Set before the crew runs — burns after first read
sirr.set("STRIPE_KEY", stripe_key, org="acme", reads=1, ttl=600)

analyst = Agent(
    role="Data Analyst",
    goal="Fetch and analyze payment data",
    tools=[stripe_tool],  # tool calls sirr.get("STRIPE_KEY", org="acme") internally
)

crew = Crew(agents=[analyst], tasks=[analysis_task])
crew.kickoff()
# STRIPE_KEY was read once by the tool — already deleted
```

### AutoGen multi-agent with isolated credentials

```python
import autogen

# Each agent gets its own scoped, expiring credential
sirr.set("AGENT_1_DB", db_url_1, org="acme", reads=5, ttl=3600)
sirr.set("AGENT_2_DB", db_url_2, org="acme", reads=5, ttl=3600)

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
    server="https://sirrlock.com",
    token=os.environ["SIRR_TOKEN"],
)

# Org is now per-call on set() and get()
sirr.set("DB_URL", "postgres://...", org="acme", reads=3)
value = sirr.get("DB_URL", org="acme")

# Audit, list, and webhook calls still support org at the client level
sirr_acme = SirrClient(server="https://sirrlock.com", token=..., org="acme")
events = sirr_acme.get_audit_log()
```

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

async with AsyncSirrClient(server=..., token=...) as sirr:
    await sirr.set("KEY", "value", org="acme")
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
