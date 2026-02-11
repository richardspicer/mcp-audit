"""Command Injection scanner (MCP05).

Tests MCP tool parameters for command injection vulnerabilities by
injecting payloads with canary markers and checking if they appear
in tool responses, indicating the input reached a shell.

Maps to: OWASP MCP Top 10 — MCP05: Command Injection via Tools
"""

from __future__ import annotations

import logging
from typing import Any

from mcp_audit.payloads.injection import get_injection_payloads
from mcp_audit.scanner.base import BaseScanner, Finding, ScanContext, Severity

logger = logging.getLogger("mcp_audit.scanner.injection")


# Default safe values for non-target parameters so the tool
# call has a reasonable chance of executing.
_SAFE_DEFAULTS: dict[str, Any] = {
    "string": "test",
    "integer": 1,
    "number": 1.0,
    "boolean": True,
    "array": [],
    "object": {},
}


def _get_string_params(tool: dict[str, Any]) -> list[str]:
    """Extract names of string-type parameters from a tool's input schema.

    Args:
        tool: Tool dict from ScanContext.tools.

    Returns:
        List of parameter names that accept string input.
    """
    schema = tool.get("inputSchema", {})
    properties = schema.get("properties", {})
    return [name for name, prop in properties.items() if prop.get("type") == "string"]


def _build_args(
    tool: dict[str, Any],
    target_param: str,
    inject_value: str,
) -> dict[str, Any]:
    """Build a tool argument dict with one parameter injected.

    Sets the target parameter to the injection payload and fills
    all other parameters with safe defaults based on their types.

    Args:
        tool: Tool dict from ScanContext.tools.
        target_param: The parameter to inject into.
        inject_value: The injection payload string.

    Returns:
        Dict of parameter name -> value, ready for call_tool().
    """
    schema = tool.get("inputSchema", {})
    properties = schema.get("properties", {})
    args: dict[str, Any] = {}

    for name, prop in properties.items():
        if name == target_param:
            args[name] = inject_value
        else:
            param_type = prop.get("type", "string")
            args[name] = _SAFE_DEFAULTS.get(param_type, "test")

    return args


def _extract_text(result: Any) -> str:
    """Extract text content from an MCP call_tool result.

    The MCP SDK returns results with a .content list containing
    TextContent, ImageContent, etc. We extract all text parts.

    Args:
        result: The CallToolResult from session.call_tool().

    Returns:
        Concatenated text content from the result.
    """
    if result is None:
        return ""

    parts: list[str] = []
    for block in getattr(result, "content", []):
        if hasattr(block, "text"):
            parts.append(block.text)
    return "\n".join(parts)


class InjectionScanner(BaseScanner):
    """Scanner for command injection via MCP tools (MCP05).

    For each tool, identifies string parameters, injects shell
    metacharacter payloads, calls the tool, and checks if the
    canary marker appears in the response.

    A canary in the response proves the input reached a shell
    and was executed — a confirmed command injection vulnerability.

    Attributes:
        name: Scanner identifier used in CLI (--checks injection).
        owasp_id: OWASP MCP Top 10 category.
        description: What this scanner tests.
    """

    name = "injection"
    owasp_id = "MCP05"
    description = "Tests for command injection via MCP tool parameters"

    async def scan(self, context: ScanContext) -> list[Finding]:
        """Test all tools for command injection vulnerabilities.

        Args:
            context: ScanContext with tools list and active session.

        Returns:
            List of Findings for each confirmed injection.

        Raises:
            ValueError: If context.session is None.
        """
        if context.session is None:
            raise ValueError("InjectionScanner requires an active session in ScanContext")

        findings: list[Finding] = []
        payloads = get_injection_payloads(platform="all")

        for tool in context.tools:
            tool_name = tool.get("name", "unknown")
            string_params = _get_string_params(tool)

            if not string_params:
                logger.debug("Skipping %s — no string parameters", tool_name)
                continue

            logger.info(
                "Testing %s — %d string params × %d payloads",
                tool_name,
                len(string_params),
                len(payloads),
            )

            for param_name in string_params:
                for payload in payloads:
                    finding = await self._test_param(context, tool, tool_name, param_name, payload)
                    if finding:
                        findings.append(finding)
                        # One confirmed injection per param is enough —
                        # skip remaining payloads for this param.
                        break

        return findings

    async def _test_param(
        self,
        context: ScanContext,
        tool: dict[str, Any],
        tool_name: str,
        param_name: str,
        payload,
    ) -> Finding | None:
        """Test a single parameter with a single payload.

        Args:
            context: Active ScanContext.
            tool: The tool dict.
            tool_name: Name of the tool being tested.
            param_name: The parameter to inject into.
            payload: The InjectionPayload to test.

        Returns:
            A Finding if injection is confirmed, None otherwise.
        """
        args = _build_args(tool, param_name, payload.value)

        try:
            result = await context.session.call_tool(tool_name, args)
            response_text = _extract_text(result)
        except Exception as exc:
            logger.debug(
                "Tool call failed: %s.%s with %s — %s",
                tool_name,
                param_name,
                payload.technique,
                exc,
            )
            return None

        if payload.canary in response_text:
            # Guard against false positives from tools that reflect input:
            # if the full payload string appears in the response, the canary
            # is likely just reflected, not executed by a shell.
            if payload.value in response_text:
                logger.debug(
                    "Canary found but full payload reflected — likely echo, not injection: "
                    "%s.%s via %s",
                    tool_name,
                    param_name,
                    payload.technique,
                )
                return None

            logger.warning(
                "INJECTION CONFIRMED: %s.%s via %s",
                tool_name,
                param_name,
                payload.technique,
            )
            return Finding(
                rule_id=f"MCP05-{payload.technique}",
                owasp_id="MCP05",
                title=f"Command injection in '{tool_name}' parameter '{param_name}'",
                description=(
                    f"The '{param_name}' parameter of tool '{tool_name}' is vulnerable "
                    f"to command injection via {payload.technique}. The injected payload "
                    f"was executed by a shell, confirmed by canary marker in the response."
                ),
                severity=Severity.CRITICAL,
                evidence=f"Payload: {payload.value!r} | Canary found in response",
                remediation=(
                    "Never pass user-controlled input to shell commands. "
                    "Use parameterized APIs (e.g., subprocess with shell=False "
                    "and explicit argument lists) instead of string interpolation."
                ),
                tool_name=tool_name,
                metadata={
                    "parameter": param_name,
                    "technique": payload.technique,
                    "platform": payload.platform,
                    "payload": payload.value,
                },
            )

        return None
