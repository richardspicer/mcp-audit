# mcp-audit

[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![pre-commit](https://img.shields.io/badge/pre--commit-enabled-brightgreen?logo=pre-commit&logoColor=white)](https://github.com/pre-commit/pre-commit)

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

### Planned Enhancements

- **Schema-derived adversarial payloads** — auto-generate CWE-mapped payloads from tool JSON schemas, constrained to LLM-plausible inputs
- **Fingerprinting in `enumerate`** — framework signature detection (FastMCP/official SDK/custom), auth method detection, known CVE matching against tool signatures

### Manual Testing Companion

For interactive MCP traffic inspection, modification, and replay, see [mcp-proxy](https://github.com/richardspicer/mcp-proxy) — the manual testing counterpart to mcp-audit's automated scanning.

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

Part of the [CounterAgent](https://github.com/richardspicer/counteragent) research program — open source security tooling for testing attack chains targeting autonomous AI agents.

## Legal

This tool is intended for authorized security testing only. Only test systems you own, control, or have explicit permission to test. See [LICENSE](LICENSE) for terms.

## License

Apache 2.0

## AI Disclosure

This project uses a human-led, AI-augmented workflow. See [AI-STATEMENT.md](AI-STATEMENT.md).
