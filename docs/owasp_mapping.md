# OWASP MCP Top 10 — Scanner Mapping

How `mcp-audit` maps to the [OWASP MCP Top 10](https://owasp.org/www-project-mcp-top-10/) vulnerability taxonomy.

**OWASP MCP Top 10 Status:** Phase 3 Beta Release (as of early 2026)
**License:** CC BY-NC-SA 4.0
**Last reviewed:** 2026-02-10

---

## Coverage Overview

| OWASP ID | Vulnerability | Scanner Module | Status | Priority |
|----------|--------------|----------------|--------|----------|
| MCP01 | Token Mismanagement & Secret Exposure | `token_exposure.py` | Planned | Medium |
| MCP02 | Privilege Escalation via Scope Creep | `permissions.py` | Planned | High |
| MCP03 | Tool Poisoning | `tool_poisoning.py` | Planned | High |
| MCP04 | Software Supply Chain Attacks | `supply_chain.py` | Planned | Low |
| MCP05 | Command Injection & Execution | `injection.py` | ✅ Built | — |
| MCP06 | Prompt Injection via Contextual Payloads | `prompt_injection.py` | Planned | Medium-High |
| MCP07 | Insufficient Authentication & Authorization | `auth.py` | Planned | **High — next** |
| MCP08 | Lack of Audit and Telemetry | `logging_audit.py` | Planned | Medium |
| MCP09 | Shadow MCP Servers | `shadow_detection.py` | Planned | Low |
| MCP10 | Context Injection & Over-Sharing | `context_sharing.py` | Planned | Medium |

### Testability Split

Some categories are directly testable by an automated scanner. Others require agent-level
testing or manual assessment and are partially covered in Phase 1 with deeper coverage in later phases.

**Directly testable by mcp-audit:** MCP01, MCP02, MCP05, MCP06, MCP07, MCP08
**Partially testable (static analysis only):** MCP03, MCP04, MCP10
**Better suited for agent-inject / manual assessment:** MCP09

---

## Per-Category Detail

### MCP01: Token Mismanagement & Secret Exposure

**Scanner module:** `scanner/token_exposure.py`

Hard-coded credentials, long-lived tokens, and secrets stored in model memory or protocol
logs. MCP systems enable long-lived sessions and context persistence, making the
model/protocol layer itself an unintentional secret repository.

**Testing approach:**

- **Tool parameter inspection** — enumerate all tool schemas and flag parameters named
  `token`, `api_key`, `secret`, `password`, `credential`, `auth`, or similar.
- **Tool response scanning** — call tools with benign inputs, scan responses for patterns
  matching API keys, JWTs, or bearer tokens. Regex targets: `eyJ` (JWT), `sk-` (OpenAI),
  `ghp_` (GitHub), `AKIA` (AWS), `xoxb-` (Slack), and others.
- **Environment variable leakage** — check for leaked secrets in tool output or error messages.
- **Log exposure check** — if the server exposes logging or debug endpoints, check for
  unredacted tokens.
- **Configuration audit** — parse MCP server config files (if accessible) for hard-coded
  credentials.

**Related CVEs:** CVE-2025-6514 (mcp-remote — token in OAuth URL flow)

---

### MCP02: Privilege Escalation via Scope Creep

**Scanner module:** `scanner/permissions.py`

Loosely defined permissions that expand over time, granting agents excessive capabilities.
Especially dangerous because agents act autonomously — an over-privileged agent can trigger
deployments or access sensitive data without human review.

**Testing approach:**

- **Excessive tool count** — flag servers exposing an unusually high number of tools (surface
  area indicator).
- **Dangerous capability analysis** — categorize tools by risk. Flag tools that perform file
  writes, shell execution, network requests, database operations, or credential management.
- **Permission granularity check** — analyze tool schemas for overly broad parameter types
  (e.g., accepting arbitrary paths, URLs, or commands without constraints).
- **Read vs. write ratio** — flag servers where write/execute tools significantly outnumber
  read-only tools.
- **Missing input constraints** — tools with string parameters that accept unbounded input
  without enumeration or pattern restrictions.

**Cross-reference:** MCP01 + MCP02 = exponential impact. A stolen token with excessive
scopes can access far more resources than intended (Microsoft Azure Security Guide).

---

### MCP03: Tool Poisoning

**Scanner module:** `scanner/tool_poisoning.py`

An adversary compromises tools, plugins, or their outputs to manipulate model behavior.
Sub-techniques include rug pulls (malicious updates to trusted tools), schema poisoning
(corrupting interface definitions), and tool shadowing (introducing fake or duplicate tools).

**Testing approach (Phase 1 — static analysis):**

- **Tool description analysis** — scan descriptions for suspicious patterns: embedded
  instructions, `<IMPORTANT>` tags, social-engineering phrases, hidden directives.
- **Description length anomaly** — flag unusually long tool descriptions that may contain
  hidden instructions.
- **Duplicate tool detection** — check for tools with similar names or overlapping
  functionality (tool shadowing indicator).
- **Schema consistency check** — verify tool input/output schemas are well-formed and don't
  contain unexpected fields.
- **Hidden character detection** — scan descriptions for Unicode tricks, zero-width
  characters, homoglyph attacks.

**Phase 2 coverage:** Dynamic tool poisoning testing moves to `agent-inject` where full
agent behavior can be observed.

**Related CVEs:** GPT-4.1 jailbreak via tool description poisoning (April 2025), Invariant
Labs WhatsApp exfiltration via malicious MCP server.

---

### MCP04: Software Supply Chain Attacks & Dependency Tampering

**Scanner module:** `scanner/supply_chain.py`

Compromised dependencies altering agent behavior or introducing execution-level backdoors.

**Testing approach (light-touch):**

- **Dependency enumeration** — if the server exposes package metadata, check against known
  vulnerability databases.
- **Version pinning check** — flag servers using unpinned or wildcard dependency versions.
- **Package provenance** — check if server packages are signed or come from verified sources.

**Note:** This is primarily a CI/CD pipeline concern. The scanner provides awareness checks
rather than deep analysis.

**Attack chain role:** MCP04 delivers MCP03, which enables MCP05 (supply chain → tool
poisoning → command injection).

---

### MCP05: Command Injection & Execution ✅ Built

**Scanner module:** `scanner/injection.py`

AI agent constructs and executes system commands using untrusted input without proper
validation. Analogous to classic injection (XSS, SQLi) but the interpreter is the model and
the payload is natural language.

**Current implementation:**

- 11 payloads (7 Unix + 4 Windows) covering `;`, `|`, `&&`, `||`, command substitution,
  newline injection.
- Canary-based detection (`MCP_AUDIT_CANARY_7f3a9b2e`).
- False-positive guard (rejects findings where full payload is reflected verbatim).
- Breaks after first confirmed injection per parameter.

**Planned enhancements based on CVE patterns:**

- `exec`/`execFile` detection payloads targeting Node.js servers using `child_process.exec`
  with `shell: true`.
- URL-based injection payloads mirroring CVE-2025-6514 (OAuth URL parameter injection).
- Windows PowerShell `$(...)` subexpression evaluation payloads.
- Pipe command payloads for data exfiltration chains.
- Timing-based detection for blind injection (`sleep`/`timeout` payloads).

**Related CVEs:**

| CVE | Component | CVSS | Root Cause |
|-----|-----------|------|------------|
| CVE-2025-6514 | mcp-remote | 9.6 | OS command injection via crafted OAuth `authorization_endpoint` URL |
| CVE-2025-49596 | MCP Inspector | 9.4 | Unauthenticated stdio command execution via proxy |
| CVE-2025-53967 | figma-developer-mcp | Critical | `child_process.exec` with unsanitized URL input |
| CVE-2025-5277 | aws-mcp-server | — | Command injection via crafted prompts to `cli_executor.py` |

---
### MCP06: Prompt Injection via Contextual Payloads

**Scanner module:** `scanner/prompt_injection.py`

Untrusted content containing hidden instructions that influence agent behavior. In MCP
systems, agents merge retrieved context with instruction templates before invoking tools.
If retrieved context is not treated as untrusted data, attackers can embed imperative
instructions.

**Testing approach:**

- **Tool output injection test** — embed prompt injection payloads in tool responses, check
  if the server processes them unsafely.
- **Metadata field injection** — test tool description fields, resource URIs, and prompt
  templates for injection susceptibility.
- **Context boundary analysis** — check if the server separates system instructions from
  user-provided context.

**Phase 2 coverage:** Full prompt injection effectiveness testing (success rate measurement
across agent configurations) moves to `agent-inject`.

---

### MCP07: Insufficient Authentication & Authorization

**Scanner module:** `scanner/auth.py`

MCP servers that fail to properly verify identities or enforce access controls.
CVE-2025-49596 is the poster child: MCP Inspector proxy accepted arbitrary stdio commands
without authentication and bound to `0.0.0.0` by default. 560+ exposed instances were
found on Shodan.

**Testing approach:**

- **Unauthenticated access test** — connect without credentials. Can you enumerate tools
  and call them?
- **Transport security check** — is the server using TLS/HTTPS? Flag unencrypted
  connections.
- **Origin validation** — send requests with spoofed origin headers.
- **CORS configuration** — check for `Access-Control-Allow-Origin: *`.
- **Session management** — check if server issues and expires session tokens.
- **Default port detection** — flag well-known default ports (6274, 6277) without
  authentication.
- **Binding check** — detect if server binds to `0.0.0.0` (network-accessible) vs
  `127.0.0.1` (localhost only).

**Cross-reference:** MCP07 is foundational. Proper auth validates tokens (MCP01), enforces
least privilege (MCP02), and prevents cross-tenant leakage (MCP10). (Microsoft Azure
Security Guide)

**Related CVEs:** CVE-2025-49596 (MCP Inspector — no auth, 0.0.0.0 binding, CSRF via
browser)

---

### MCP08: Lack of Audit and Telemetry

**Scanner module:** `scanner/logging_audit.py`

Without comprehensive logging and alerting, unauthorized actions go undetected. MCP08 makes
all other risks harder to detect (Microsoft Azure Security Guide).

**Testing approach:**

- **Logging capability check** — does the server expose logging configuration?
- **Error disclosure** — trigger intentional errors. Does the server leak stack traces, file
  paths, or internal details?
- **Telemetry endpoint detection** — check for exposed metrics endpoints (Prometheus, etc.).

---

### MCP09: Shadow MCP Servers

**Scanner module:** `scanner/shadow_detection.py`

Unapproved MCP server deployments operating outside formal security governance. The MCP
equivalent of Shadow IT.

**Testing approach:**

- **Network scanning mode** — scan for common MCP ports and endpoints.
- **Default configuration detection** — flag default settings: no auth, binding to `0.0.0.0`,
  default ports.
- **Server fingerprinting** — identify MCP server implementations by initialization
  responses.

**Note:** Low priority for Phase 1. This is more of a network scanning concern than a
per-server audit. May be better suited to a standalone utility or integration with existing
network scanners.

---

### MCP10: Context Injection & Over-Sharing

**Scanner module:** `scanner/context_sharing.py`

Context windows that are shared, persistent, or insufficiently scoped, causing information
leakage between sessions, agents, or users.

**Testing approach:**

- **Session isolation test** — connect with two sessions, check for data leakage between
  them.
- **Context persistence check** — disconnect and reconnect. Does the server retain previous
  context?
- **Resource isolation** — check if resources are scoped to the current session or user.

**Note:** Important for multi-tenant deployments. Harder to automate for single-server scans
but basic isolation tests are feasible.

---

## Attack Chain Relationships

Categories don't exist in isolation. The OWASP MCP Top 10 categories compose into attack
chains (informed by the Microsoft Azure Security Guide for MCP):

```
MCP04 (Supply Chain) → delivers → MCP03 (Tool Poisoning) → enables → MCP05 (Command Injection)

MCP01 (Token Leak) + MCP02 (Excessive Scope) = Exponential impact

MCP07 (Weak Auth) = Foundational — validates tokens (MCP01),
                     enforces least privilege (MCP02),
                     prevents cross-tenant leakage (MCP10)

MCP08 (No Telemetry) = All other risks become harder to detect

MCP09 (Shadow Servers) = Bypass all centralized security policies
```

These chains inform testing priority. MCP07 (auth) is the foundation — if auth is broken,
MCP01, MCP02, and MCP10 weaknesses become directly exploitable.

---

## CVE Reference

Known CVEs mapped to OWASP MCP Top 10 categories:

| CVE | CVSS | Component | OWASP Category | Summary |
|-----|------|-----------|----------------|---------|
| CVE-2025-6514 | 9.6 | mcp-remote v0.0.5–v0.1.15 | MCP05, MCP01 | OS command injection via crafted OAuth URL |
| CVE-2025-49596 | 9.4 | MCP Inspector < 0.14.1 | MCP07, MCP05 | Unauthenticated RCE via stdio proxy |
| CVE-2025-53967 | Critical | figma-developer-mcp | MCP05 | `child_process.exec` injection via unsanitized URL |
| CVE-2025-5277 | — | aws-mcp-server | MCP05 | Command injection via crafted prompts |
| CVE-2025-53110 | 7.3 | Anthropic Filesystem MCP | MCP02 | Directory containment bypass via prefix tricks |
| CVE-2025-53109 | 8.4 | Anthropic Filesystem MCP | MCP02, MCP05 | Symlink bypass enabling arbitrary file access and code execution |

---

## References

- [OWASP MCP Top 10](https://owasp.org/www-project-mcp-top-10/)
- [OWASP Top 10 for Agentic AI](https://owasp.org/www-project-top-10-for-agentic-ai/)
- [Microsoft Azure: MCP Security Guidance](https://learn.microsoft.com/en-us/azure/ai-services/agents/concepts/model-context-protocol-security)
- [MITRE ATLAS](https://atlas.mitre.org/) — adversarial ML technique mapping
- [NIST AI RMF](https://www.nist.gov/artificial-intelligence/risk-management-framework) — risk management context
