# sirr (Python)

Python client for [Sirr](https://github.com/SirrVault/sirr) — ephemeral secret management.

> Work in progress.

## Install

```bash
pip install sirr
```

## Usage

```python
import os
from sirr import SirrClient

sirr = SirrClient(
    server=os.environ.get("SIRR_SERVER", "http://localhost:8080"),
    token=os.environ["SIRR_TOKEN"],
)

# Push a one-time secret
sirr.push("API_KEY", "sk-...", ttl=3600, reads=1)

# Retrieve (None if burned or expired)
value = sirr.get("API_KEY")

# Pull all secrets into a dict
secrets = sirr.pull_all()

# Inject as env vars for the duration of a block
with sirr.env():
    # os.environ["API_KEY"] is set here
    run_tests()

# Delete immediately
sirr.delete("API_KEY")
```

## Related

- [SirrVault/sirr](https://github.com/SirrVault/sirr) — server
- [SirrVault/cli](https://github.com/SirrVault/cli) — CLI
- [SirrVault/node](https://github.com/SirrVault/node) — Node.js client
- [SirrVault/dotnet](https://github.com/SirrVault/dotnet) — .NET client
