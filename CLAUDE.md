# mcp-audit

MCP server security scanner mapping findings to OWASP MCP Top 10. Part of the CounterAgent research program under richardspicer.io.

## Project Layout

```
src/mcp_audit/
├── cli.py                    # Typer CLI (scan, list-checks, enumerate)
├── orchestrator.py           # connect → enumerate → scan → report pipeline
├── mcp_client/               # MCP connection (stdio, SSE, Streamable HTTP)
│   ├── connector.py         # Transport-level connection management
│   └── discovery.py          # Server enumeration, populates ScanContext
├── scanner/
│   ├── base.py               # BaseScanner, Finding, ScanContext, Severity
│   ├── registry.py           # Scanner registry (add new scanners here)
│   ├── injection.py          # MCP05 — command injection via tool params
│   ├── auth.py               # MCP07 — authentication & transport checks
│   ├── permissions.py        # MCP02 — privilege escalation, tool analysis
│   ├── tool_poisoning.py     # MCP03 — poisoned descriptions, Unicode tricks
│   ├── prompt_injection.py   # MCP06 — injection patterns in tool responses
│   └── audit_telemetry.py    # MCP08 — logging, error disclosure, metadata
├── payloads/                 # Payload libraries per attack category
├── reporting/                # JSON output (SARIF planned)
└── utils/
fixtures/vulnerable_servers/  # FastMCP-based intentionally vulnerable servers
tests/test_scanners/          # One test file per scanner module
```

## Scanner Architecture

All scanners inherit from `BaseScanner` in `base.py` and implement:

```python
async def scan(self, context: ScanContext) -> list[Finding]
```

Scanner types:
- **Static** (permissions, tool_poisoning): Analyze `context.tools` metadata only
- **Active** (injection, prompt_injection): Call tools via `context.session`
- **Hybrid** (audit_telemetry): Check metadata + trigger errors actively
- **Connection-level** (auth): Check transport, ports, TLS

Findings use rule IDs like `MCP07-001` (OWASP category + sequential check number).

### Adding a New Scanner

1. Create `src/mcp_audit/scanner/<name>.py` — inherit `BaseScanner`, set `name`, `owasp_id`, `description`
2. Create `fixtures/vulnerable_servers/vuln_<name>.py` — FastMCP server that triggers findings
3. Create `tests/test_scanners/test_<name>.py` — integration tests against fixture + synthetic tests
4. Register in `registry.py` — add import and entry to `_REGISTRY` dict
5. Run full test suite and CLI smoke test before committing

### Reusable Helpers

- `tool_poisoning.py` has `_find_injection_patterns()` and `_find_hidden_unicode()` — reused by `prompt_injection.py`
- `auth.py` has sensitive tool classification via keyword matching
- Levenshtein distance in `tool_poisoning.py` for name similarity

## Code Standards

- **Docstrings:** Google-style on all public functions and classes (Args, Returns, Raises, Example)
- **Async:** MCP SDK is async-native. Scanners and client code use `async/await`
- **Type hints:** Required on all function signatures
- **Line length:** 100 chars (ruff)
- **Imports:** Sorted by ruff (isort rules)

## Testing

- Framework: pytest + pytest-asyncio (asyncio_mode = "auto")
- Each scanner gets `tests/test_scanners/test_<name>.py`
- Integration tests connect to fixture servers via `MCPConnection.stdio`
- Synthetic tests construct `ScanContext` directly for unit-level checks
- Helper functions get their own unit tests
- **All tests must pass before committing**

Run tests:
```
uv run pytest -q
```

Smoke test:
```
mcp-audit list-checks
```

## Git Workflow

**Never commit directly to main.** Branch protection enforced.

```
git checkout main && git pull
git checkout -b feature/description    # or fix/, docs/, refactor/
# ... work ...
uv run pytest -q                       # all tests pass
mcp-audit list-checks                  # CLI smoke test
git add .
git commit -F .commitmsg               # see shell quoting note below
git push -u origin feature/description
# Create PR on GitHub, merge after CodeQL passes
```

### Shell Quoting (CRITICAL)

The CMD shell corrupts `git commit -m "message with spaces"`. Always use:
```
echo "feat: description here" > .commitmsg
git commit -F .commitmsg
rm .commitmsg
```

This applies to any shell command where arguments contain spaces, commas, or parentheses.

### End of Session

Commit to branch, `git stash -m "description"`, or `git restore .` — never leave uncommitted changes.

## Pre-commit Hooks

Hooks run automatically on `git commit`:
- trailing-whitespace, end-of-file-fixer, check-yaml, check-toml
- check-added-large-files, check-merge-conflict
- **no-commit-to-branch** (blocks direct commits to main)
- **ruff-check** (lint + auto-fix) + **ruff-format**
- **gitleaks** (secrets detection)
- **mypy** (type checking)

If pre-commit fails, fix issues and re-stage before committing.

## Dependencies

Managed via `uv` with `pyproject.toml`. Sync with:
```
uv sync --group dev
```

**Without `--group dev`, dev dependencies get stripped.**

## Key Patterns to Follow

- Findings include: rule_id, owasp_id, title, description, severity, evidence, remediation, metadata
- Severity escalation: some checks start MEDIUM and escalate to HIGH/CRITICAL based on context
- Fixtures include both vulnerable AND benign tools to test threshold logic
- Fixture servers are runnable: `python -m fixtures.vulnerable_servers.vuln_<name>`
- Test file naming matches scanner: `test_<scanner_name>.py`

- **`docs/Architecture.md`:** Update at end of session if new modules, endpoints, or data models were introduced

## CLI Usage

```powershell
mcp-audit scan --transport stdio --command "python my_server.py"
mcp-audit scan --transport sse --url http://localhost:8080/sse
mcp-audit scan --transport stdio --command "python my_server.py" --checks injection,auth
mcp-audit list-checks
mcp-audit enumerate --transport stdio --command "python my_server.py"
mcp-audit report --input results/scan.json --format html
```

After changes, smoke test: `mcp-audit list-checks`

## Legal & Ethical

- Only test systems you own, control, or have explicit permission to test
- Responsible disclosure for all vulnerabilities — never publish exploits before vendor notification
- Frame all tooling as defensive security testing tools (analogous to Metasploit, Burp Suite)
