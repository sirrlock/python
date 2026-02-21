# sirr (Python)

**Ephemeral secrets for Python AI agents. Credentials that delete themselves.**

`sirr` is the Python client for [Sirr](https://github.com/SirrVault/sirr) — a self-hosted vault where every secret expires by read count, by time, or both. Built for the Python AI ecosystem: LangChain, CrewAI, AutoGen, LlamaIndex, and any framework that needs to hand credentials to agents without leaving them lying around forever.

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
    server=os.environ.get("SIRR_SERVER", "http://localhost:8080"),
    token=os.environ["SIRR_TOKEN"],
)

# Push a one-time secret
sirr.push("API_KEY", "sk-...", reads=1, ttl=3600)

# Retrieve — None if burned or expired
value = sirr.get("API_KEY")

# Pull all secrets into a dict
secrets = sirr.pull_all()
# → {"API_KEY": "sk-...", "DB_URL": "postgres://..."}

# Inject as environment variables for the duration of a block
with sirr.env():
    # os.environ["API_KEY"] is set here
    run_agent_task()
    # restored on exit, even on exception

# Delete immediately
sirr.delete("API_KEY")

# List active secrets (metadata only — no values)
entries = sirr.list()

# Prune expired secrets
pruned = sirr.prune()
```

### Async

```python
from sirr import AsyncSirrClient

async with AsyncSirrClient(server=..., token=...) as sirr:
    await sirr.push("API_KEY", "sk-...", reads=1, ttl=3600)
    value = await sirr.get("API_KEY")
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

## Related

- [SirrVault/sirr](https://github.com/SirrVault/sirr) — server
- [SirrVault/cli](https://github.com/SirrVault/cli) — CLI
- [SirrVault/node](https://github.com/SirrVault/node) — Node.js client
- [SirrVault/dotnet](https://github.com/SirrVault/dotnet) — .NET client
