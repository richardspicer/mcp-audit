"""Tests for the authentication scanner (MCP07).

Runs the auth scanner against the vulnerable fixture server
and verifies it correctly identifies authentication weaknesses.
"""

import sys

import pytest

from mcp_audit.mcp_client.connector import MCPConnection
from mcp_audit.mcp_client.discovery import enumerate_server
from mcp_audit.scanner.auth import AuthScanner, _classify_tool_sensitivity, _extract_url_components
from mcp_audit.scanner.base import ScanContext

VULN_AUTH_SERVER = "fixtures/vulnerable_servers/vuln_auth.py"
PYTHON = sys.executable


class TestAuthScanner:
    """Test the auth scanner against the fixture server."""

    @pytest.mark.asyncio
    async def test_finds_unauth_enumeration(self):
        """Scanner detects unauthenticated capability enumeration."""
        async with MCPConnection.stdio(
            command=PYTHON,
            args=[VULN_AUTH_SERVER],
        ) as conn:
            ctx = await enumerate_server(conn)
            scanner = AuthScanner()
            findings = await scanner.scan(ctx)

            enum_findings = [f for f in findings if f.rule_id == "MCP07-001"]
            assert len(enum_findings) == 1, "Should detect unauthenticated enumeration"
            assert enum_findings[0].owasp_id == "MCP07"

    @pytest.mark.asyncio
    async def test_finds_unauth_invocation(self):
        """Scanner detects unauthenticated tool invocation."""
        async with MCPConnection.stdio(
            command=PYTHON,
            args=[VULN_AUTH_SERVER],
        ) as conn:
            ctx = await enumerate_server(conn)
            scanner = AuthScanner()
            findings = await scanner.scan(ctx)

            invoke_findings = [f for f in findings if f.rule_id == "MCP07-002"]
            assert len(invoke_findings) == 1, "Should detect unauthenticated invocation"

    @pytest.mark.asyncio
    async def test_sensitive_tools_escalate_severity(self):
        """Sensitive tools should escalate finding severity."""
        async with MCPConnection.stdio(
            command=PYTHON,
            args=[VULN_AUTH_SERVER],
        ) as conn:
            ctx = await enumerate_server(conn)
            scanner = AuthScanner()
            findings = await scanner.scan(ctx)

            enum_finding = next(f for f in findings if f.rule_id == "MCP07-001")
            # vuln_auth has sensitive tools (read_config, list_secrets, execute_query)
            assert enum_finding.severity.value == "high"
            assert len(enum_finding.metadata["sensitive_tools"]) >= 1

    @pytest.mark.asyncio
    async def test_no_tls_check_skipped_for_stdio(self):
        """TLS check should not fire for stdio transport."""
        async with MCPConnection.stdio(
            command=PYTHON,
            args=[VULN_AUTH_SERVER],
        ) as conn:
            ctx = await enumerate_server(conn)
            scanner = AuthScanner()
            findings = await scanner.scan(ctx)

            tls_findings = [f for f in findings if f.rule_id == "MCP07-003"]
            assert len(tls_findings) == 0, "TLS check should skip for stdio"

    @pytest.mark.asyncio
    async def test_default_port_skipped_for_stdio(self):
        """Default port check should not fire for stdio transport."""
        async with MCPConnection.stdio(
            command=PYTHON,
            args=[VULN_AUTH_SERVER],
        ) as conn:
            ctx = await enumerate_server(conn)
            scanner = AuthScanner()
            findings = await scanner.scan(ctx)

            port_findings = [f for f in findings if f.rule_id == "MCP07-004"]
            assert len(port_findings) == 0, "Port check should skip for stdio"

    @pytest.mark.asyncio
    async def test_finding_has_remediation(self):
        """Each finding includes remediation guidance."""
        async with MCPConnection.stdio(
            command=PYTHON,
            args=[VULN_AUTH_SERVER],
        ) as conn:
            ctx = await enumerate_server(conn)
            scanner = AuthScanner()
            findings = await scanner.scan(ctx)

            for f in findings:
                assert f.remediation, f"Finding {f.rule_id} missing remediation"

    @pytest.mark.asyncio
    async def test_stdio_produces_exactly_two_findings(self):
        """Stdio fixture should produce exactly 2 findings (enum + invoke)."""
        async with MCPConnection.stdio(
            command=PYTHON,
            args=[VULN_AUTH_SERVER],
        ) as conn:
            ctx = await enumerate_server(conn)
            scanner = AuthScanner()
            findings = await scanner.scan(ctx)

            assert len(findings) == 2, (
                f"Expected 2 findings (enum + invoke) for stdio, got {len(findings)}: "
                f"{[f.rule_id for f in findings]}"
            )


class TestTransportChecks:
    """Test HTTP-specific checks using synthetic ScanContext."""

    def test_no_tls_detected(self):
        """Unencrypted HTTP connection should produce a finding."""
        ctx = ScanContext(
            transport_type="sse",
            connection_url="http://0.0.0.0:8080/sse",
        )
        scanner = AuthScanner()
        finding = scanner._check_transport_encryption(ctx)

        assert finding is not None
        assert finding.rule_id == "MCP07-003"
        assert finding.severity.value == "high"

    def test_tls_passes(self):
        """HTTPS connection should not produce a finding."""
        ctx = ScanContext(
            transport_type="sse",
            connection_url="https://secure.example.com/sse",
        )
        scanner = AuthScanner()
        finding = scanner._check_transport_encryption(ctx)

        assert finding is None

    def test_default_port_detected(self):
        """Well-known MCP port should produce a finding."""
        ctx = ScanContext(
            transport_type="sse",
            connection_url="http://localhost:6274/sse",
        )
        scanner = AuthScanner()
        finding = scanner._check_default_port(ctx)

        assert finding is not None
        assert finding.rule_id == "MCP07-004"
        assert "6274" in finding.description

    def test_non_default_port_passes(self):
        """Non-default port should not produce a finding."""
        ctx = ScanContext(
            transport_type="sse",
            connection_url="http://localhost:9090/sse",
        )
        scanner = AuthScanner()
        finding = scanner._check_default_port(ctx)

        assert finding is None


class TestHelpers:
    """Test helper functions."""

    def test_classify_sensitive_tool(self):
        """Tools with sensitive keywords are classified correctly."""
        assert _classify_tool_sensitivity({"name": "read_config", "description": "Read config"})
        assert _classify_tool_sensitivity({"name": "get_data", "description": "List secrets"})
        assert _classify_tool_sensitivity({"name": "execute_query", "description": "Run SQL"})

    def test_classify_benign_tool(self):
        """Tools without sensitive keywords are not flagged."""
        assert not _classify_tool_sensitivity({"name": "echo", "description": "Echo a message"})
        assert not _classify_tool_sensitivity({"name": "ping", "description": "Check health"})

    def test_url_components_http(self):
        """Parse HTTP URL components correctly."""
        components = _extract_url_components("http://0.0.0.0:6274/sse")
        assert components["scheme"] == "http"
        assert components["hostname"] == "0.0.0.0"
        assert components["port"] == 6274
        assert components["is_tls"] is False

    def test_url_components_https(self):
        """Parse HTTPS URL components correctly."""
        components = _extract_url_components("https://secure.example.com/mcp")
        assert components["scheme"] == "https"
        assert components["port"] == 443
        assert components["is_tls"] is True

    def test_url_components_default_port(self):
        """Default ports are inferred when not specified."""
        http = _extract_url_components("http://localhost/sse")
        assert http["port"] == 80

        https = _extract_url_components("https://localhost/sse")
        assert https["port"] == 443
