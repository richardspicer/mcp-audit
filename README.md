# mcp-audit

**Security auditor for MCP (Model Context Protocol) server implementations.**

Maps findings to the [OWASP MCP Top 10](https://owasp.org/www-project-mcp-top-10/) vulnerability taxonomy.

> ⚠️ **Early development** — scanner modules are actively being built. Star/watch for updates.

## What It Does

`mcp-audit` connects to MCP servers and runs automated security checks against each OWASP MCP Top 10 category:

| OWASP ID | Vulnerability | Status |
|----------|--------------|--------|
| MCP01 | Token Mismanagement | 🔜 Planned |
| MCP02 | Privilege Escalation via Tools | 🔜 Planned |
| MCP03 | Tool Poisoning | 🔜 Planned |
| MCP04 | Supply Chain & Integrity | 🔜 Planned |
| MCP05 | Command Injection via Tools | 🚧 In Progress |
| MCP06 | Indirect Prompt Injection | 🔜 Planned |
| MCP07 | Insufficient Auth/Authz | 🔜 Planned |
| MCP08 | Insufficient Audit & Telemetry | 🔜 Planned |
| MCP09 | Shadow MCP Servers | 🔜 Planned |
| MCP10 | Context Over-Sharing | 🔜 Planned |

## Installation

Requires Python 3.11+.

Requires [uv](https://docs.astral.sh/uv/) for dependency management.

```bash
# Clone and install in development mode
git clone https://github.com/richardspicer/mcp-audit.git
cd mcp-audit
uv sync
```

## Usage

```bash
# Scan a local stdio-based MCP server
mcp-audit scan --transport stdio --command "python my_server.py"

# Scan an SSE server
mcp-audit scan --transport sse --url http://localhost:8080/sse

# Run specific checks only
mcp-audit scan --transport stdio --command "python my_server.py" --checks injection,auth

# List available scanner modules
mcp-audit list-checks

# Enumerate server capabilities (no scanning)
mcp-audit enumerate --transport stdio --command "python my_server.py"

# Generate report from saved results
mcp-audit report --input results/scan.json --format html
```

## Output Formats

- **JSON** — Machine-readable findings for programmatic use
- **SARIF** — GitHub Advanced Security / CI/CD integration
- **HTML** — Human-readable report with severity breakdown

## Project

Part of the [CounterAgent](https://richardspicer.io) research program — open source security tooling for testing attack chains targeting autonomous AI agents.

## Legal

This tool is intended for authorized security testing only. Only test systems you own, control, or have explicit permission to test. See [LICENSE](LICENSE) for terms.

## License

Apache 2.0

## AI Disclosure

This project uses a human-led, AI-augmented workflow. See [AI-STATEMENT.md](AI-STATEMENT.md).
