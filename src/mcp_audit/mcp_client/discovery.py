"""Server capability discovery and enumeration.

Enumerates tools, resources, and prompts exposed by an MCP server
to build a ScanContext for scanner modules.
"""

from typing import Any

from mcp_audit.scanner.base import ScanContext


async def enumerate_server(session: Any) -> ScanContext:
    """Enumerate all capabilities of a connected MCP server.

    Queries the server for its tools, resources, and prompts, and
    packages the results into a ScanContext for scanner modules.

    Args:
        session: An active MCP client session.

    Returns:
        ScanContext populated with server metadata and capabilities.

    Raises:
        ConnectionError: If the server disconnects during enumeration.
    """
    # TODO: Implement using session.list_tools(), list_resources(), list_prompts()
    raise NotImplementedError("Server enumeration not yet implemented")
