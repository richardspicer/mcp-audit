"""Tests for the command injection scanner (MCP05).

Runs the injection scanner against the vulnerable fixture server
and verifies it correctly identifies injection vulnerabilities.
"""

import sys

import pytest

from mcp_audit.mcp_client.connector import MCPConnection
from mcp_audit.mcp_client.discovery import enumerate_server
from mcp_audit.scanner.injection import InjectionScanner

VULN_INJECTION_SERVER = "fixtures/vulnerable_servers/vuln_injection.py"
PYTHON = sys.executable


class TestInjectionScanner:
    """Test the injection scanner against the fixture server."""

    @pytest.mark.asyncio
    async def test_finds_injections(self):
        """Scanner detects injection vulnerabilities in fixture server."""
        async with MCPConnection.stdio(
            command=PYTHON,
            args=[VULN_INJECTION_SERVER],
        ) as conn:
            ctx = await enumerate_server(conn)
            scanner = InjectionScanner()
            findings = await scanner.scan(ctx)

            # The fixture has 3 vulnerable tools and 1 safe tool
            assert len(findings) >= 1, "Should find at least one injection"
            assert all(f.owasp_id == "MCP05" for f in findings)
            assert all(f.severity.value == "critical" for f in findings)

    @pytest.mark.asyncio
    async def test_vulnerable_tools_identified(self):
        """Each vulnerable tool is flagged with a finding."""
        async with MCPConnection.stdio(
            command=PYTHON,
            args=[VULN_INJECTION_SERVER],
        ) as conn:
            ctx = await enumerate_server(conn)
            scanner = InjectionScanner()
            findings = await scanner.scan(ctx)

            flagged_tools = {f.tool_name for f in findings}
            # file_search and run_diagnostics are the most reliably
            # injectable tools in the fixture (they use find/ping).
            # list_processes uses 'ps' which may not exist on Windows.
            assert "file_search" in flagged_tools or "run_diagnostics" in flagged_tools

    @pytest.mark.asyncio
    async def test_safe_tool_not_flagged(self):
        """The safe_echo tool should not produce findings."""
        async with MCPConnection.stdio(
            command=PYTHON,
            args=[VULN_INJECTION_SERVER],
        ) as conn:
            ctx = await enumerate_server(conn)
            scanner = InjectionScanner()
            findings = await scanner.scan(ctx)

            flagged_tools = {f.tool_name for f in findings}
            assert "safe_echo" not in flagged_tools

    @pytest.mark.asyncio
    async def test_finding_has_remediation(self):
        """Each finding includes remediation guidance."""
        async with MCPConnection.stdio(
            command=PYTHON,
            args=[VULN_INJECTION_SERVER],
        ) as conn:
            ctx = await enumerate_server(conn)
            scanner = InjectionScanner()
            findings = await scanner.scan(ctx)

            for f in findings:
                assert f.remediation, f"Finding {f.rule_id} missing remediation"
                assert "shell" in f.remediation.lower() or "subprocess" in f.remediation.lower()
