# Scan Targets

Dockerized MCP servers for security scanning with [mcp-audit](https://github.com/richardspicer/mcp-audit). Each directory contains one or more Docker images that package a specific MCP server implementation at pinned versions for reproducible security testing.

## Prerequisites

- Docker with BuildKit (Docker Engine 23.0+ or `docker-buildx` package)
- [mcp-audit](https://github.com/richardspicer/mcp-audit) installed (`pip install mcp-audit` or from source)

## Available Targets

| Directory | Server | Purpose |
|-----------|--------|---------|
| `mcp-server-git/` | [mcp-server-git](https://github.com/modelcontextprotocol/servers) | Three pinned versions spanning known CVEs — fully vulnerable, partially patched, fully patched |
| `mcp-server-sqlite/` | [mcp-server-sqlite](https://github.com/modelcontextprotocol/servers) | Anthropic's reference SQLite server with pre-populated test database |

## Quick Start

```bash
# Build a target
cd scan-targets/mcp-server-git
docker build -f Dockerfile.vuln -t mcp-git-vuln:2025.7.1 .

# Scan it with mcp-audit
mcp-audit scan --transport stdio --command "docker run --rm -i mcp-git-vuln:2025.7.1"
```

See each target directory's README for specific build commands, CVE mapping, and expected findings.

## Adding New Targets

Create a new directory named after the MCP server package. Include:

- One or more Dockerfiles (use version suffixes if pinning multiple versions)
- A `README.md` documenting the server, versions, known vulnerabilities, build commands, and scan commands
- Any supporting files (init scripts, config, seed data)

Targets should be self-contained — `docker build` from the target directory should produce a scannable image with no external dependencies.
