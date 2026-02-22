# mcp-server-git — Scan Targets

Three pinned versions of Anthropic's reference [mcp-server-git](https://pypi.org/project/mcp-server-git/) MCP server, spanning a CVE fix timeline. Use these to validate scanner detection capabilities against known vulnerabilities.

## CVE Coverage

| CVE | Description | CVSS | Vuln (2025.7.1) | Partial (2025.11.25) | Patched (2026.1.14) |
|-----|-------------|------|:---:|:---:|:---:|
| CVE-2025-68143 | Arbitrary repo init via `git_init` tool | — | ✅ | ❌ (tool removed) | ❌ |
| CVE-2025-68144 | Command injection in `git_diff`/`git_checkout` params | — | ✅ | ✅ | ❌ |
| CVE-2025-68145 | Path traversal in tool arguments | — | ✅ | ✅ | ❌ |

## Dockerfiles

| File | Image Tag | Version | Purpose |
|------|-----------|---------|---------|
| `Dockerfile.vuln` | `mcp-git-vuln:2025.7.1` | 2025.7.1 | Positive control — all CVEs present |
| `Dockerfile.partial` | `mcp-git-partial:2025.11.25` | 2025.11.25 | Partial fix — `git_init` removed, injection/traversal remain |
| `Dockerfile.patched` | `mcp-git-patched:2026.1.14` | 2026.1.14 | Negative control — all CVEs patched |

## Build

```bash
cd scan-targets/mcp-server-git

docker build -f Dockerfile.vuln -t mcp-git-vuln:2025.7.1 .
docker build -f Dockerfile.partial -t mcp-git-partial:2025.11.25 .
docker build -f Dockerfile.patched -t mcp-git-patched:2026.1.14 .
```

## Smoke Test

Each image should respond to an MCP initialize handshake on stdio:

```bash
echo '{"jsonrpc":"2.0","method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"0.1"}},"id":1}' \
  | docker run --rm -i mcp-git-vuln:2025.7.1
```

Expected: JSON-RPC response with `serverInfo` and `capabilities`.

## Scan

```bash
# Full scan with mcp-audit
mcp-audit scan --transport stdio --command "docker run --rm -i mcp-git-vuln:2025.7.1"
mcp-audit scan --transport stdio --command "docker run --rm -i mcp-git-partial:2025.11.25"
mcp-audit scan --transport stdio --command "docker run --rm -i mcp-git-patched:2026.1.14"
```

## Container Details

- **Base image:** `python:3.12-slim` with `git` installed
- **Test repo:** `/repos/test-repo` — single-commit repo with `README.md` and `src/main.py`
- **Sensitive data (vuln + patched):** `/sensitive-data/secrets.txt` — fake credentials for path traversal testing
- **Tools exposed:** 13 (vuln) / 12 (partial + patched — `git_init` removed)
