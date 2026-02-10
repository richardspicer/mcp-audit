"""MCP client library for mcp-audit.

Handles connecting to MCP servers and enumerating their capabilities.
"""

from mcp_audit.mcp_client.connector import MCPConnection
from mcp_audit.mcp_client.discovery import enumerate_server

__all__ = ["MCPConnection", "enumerate_server"]
