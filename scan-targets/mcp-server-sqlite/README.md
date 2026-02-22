# mcp-server-sqlite — Scan Target

Anthropic's reference [mcp-server-sqlite](https://pypi.org/project/mcp-server-sqlite/) MCP server with a pre-populated test database. Provides a rich attack surface with SQL query tools, resources, and prompts.

## Why This Target

- Exposes `read_query` and `write_query` tools that accept arbitrary SQL
- Known injection surface via `describe_table.table_name`
- Exposes resources (`memo://insights`) and prompts — exercises scanner modules that git targets don't
- Pre-populated with realistic test data (users, API keys, audit logs)

## Build

```bash
cd scan-targets/mcp-server-sqlite

docker build -t mcp-sqlite:latest .
```

Requires Docker with BuildKit support.

## Smoke Test

```bash
echo '{"jsonrpc":"2.0","method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"0.1"}},"id":1}' \
  | docker run --rm -i mcp-sqlite:latest
```

Expected: JSON-RPC response with `serverInfo` and `capabilities`.

## Scan

```bash
mcp-audit scan --transport stdio --command "docker run --rm -i mcp-sqlite:latest"
```

## Test Database Schema

The `init_db.py` script creates `/data/test.db` with:

| Table | Columns | Purpose |
|-------|---------|---------|
| `users` | id, name, email, role | User enumeration, role escalation testing |
| `api_keys` | id, owner, key_value, scope | Sensitive data exposure testing |
| `audit_log` | id, timestamp, action, user_id | Audit trail presence |

All credential values are synthetic (e.g., `sk-FAKE-1234567890abcdef`).

## Container Details

- **Base image:** `python:3.12-slim`
- **Database:** `/data/test.db` (SQLite, created at build time)
- **Tools exposed:** 6 (`read_query`, `write_query`, `create_table`, `list_tables`, `describe_table`, `append_insight`)
- **Resources:** 1 (`memo://insights`)
- **Prompts:** 1
