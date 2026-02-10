"""CLI entry point for mcp-audit.

Provides commands for scanning MCP servers, enumerating capabilities,
and generating reports.
"""

from typing import Optional

import typer
from rich.console import Console

app = typer.Typer(
    name="mcp-audit",
    help="Security auditor for MCP server implementations — OWASP MCP Top 10",
    no_args_is_help=True,
)
console = Console()


@app.command()
def scan(
    transport: str = typer.Option(
        ...,
        help="Transport type: 'stdio', 'sse', or 'streamable-http'",
    ),
    command: Optional[str] = typer.Option(
        None,
        help="Server command for stdio transport (e.g., 'python my_server.py')",
    ),
    url: Optional[str] = typer.Option(
        None,
        help="Server URL for SSE or Streamable HTTP transport",
    ),
    target: Optional[str] = typer.Option(
        None,
        help="Path to target configuration YAML file",
    ),
    checks: Optional[str] = typer.Option(
        None,
        help="Comma-separated list of checks to run (e.g., 'injection,auth')",
    ),
    output: str = typer.Option(
        "results/scan.json",
        help="Output file path for scan results",
    ),
    format: str = typer.Option(
        "json",
        help="Output format: 'json', 'sarif', or 'html'",
    ),
) -> None:
    """Scan an MCP server for security vulnerabilities."""
    console.print("[bold blue]mcp-audit[/bold blue] — MCP Security Scanner")
    console.print(f"Transport: {transport}")

    # TODO: Implement scan orchestration
    console.print("[yellow]Scanner not yet implemented — coming soon.[/yellow]")


@app.command(name="list-checks")
def list_checks() -> None:
    """List all available scanner modules and their OWASP mappings."""
    console.print("[bold blue]mcp-audit[/bold blue] — Available Checks\n")

    # TODO: Dynamically load from scanner registry
    checks = [
        ("injection", "MCP05", "Command Injection via Tools"),
        ("auth", "MCP07", "Insufficient Authentication/Authorization"),
        ("tokens", "MCP01", "Token Mismanagement"),
        ("permissions", "MCP02", "Privilege Escalation via Tools"),
        ("tool_poisoning", "MCP03", "Tool Poisoning"),
        ("prompt_injection", "MCP06", "Indirect Prompt Injection"),
        ("audit_telemetry", "MCP08", "Insufficient Audit & Telemetry"),
        ("supply_chain", "MCP04", "Supply Chain & Integrity"),
        ("shadow_servers", "MCP09", "Shadow MCP Servers"),
        ("context_sharing", "MCP10", "Context Over-Sharing"),
    ]

    from rich.table import Table

    table = Table(title="Scanner Modules")
    table.add_column("Module", style="cyan")
    table.add_column("OWASP ID", style="green")
    table.add_column("Description")

    for module, owasp_id, desc in checks:
        table.add_row(module, owasp_id, desc)

    console.print(table)


@app.command()
def enumerate(
    transport: str = typer.Option(
        ...,
        help="Transport type: 'stdio', 'sse', or 'streamable-http'",
    ),
    command: Optional[str] = typer.Option(
        None,
        help="Server command for stdio transport",
    ),
    url: Optional[str] = typer.Option(
        None,
        help="Server URL for SSE or Streamable HTTP transport",
    ),
) -> None:
    """Enumerate MCP server capabilities without scanning."""
    console.print("[bold blue]mcp-audit[/bold blue] — Server Enumeration")

    # TODO: Implement enumeration
    console.print("[yellow]Enumeration not yet implemented — coming soon.[/yellow]")


@app.command()
def report(
    input: str = typer.Option(
        ...,
        help="Path to saved scan results JSON file",
    ),
    format: str = typer.Option(
        "html",
        help="Report format: 'html', 'json', or 'sarif'",
    ),
    output: Optional[str] = typer.Option(
        None,
        help="Output file path (defaults to input path with new extension)",
    ),
) -> None:
    """Generate a report from saved scan results."""
    console.print("[bold blue]mcp-audit[/bold blue] — Report Generator")

    # TODO: Implement report generation
    console.print("[yellow]Report generation not yet implemented — coming soon.[/yellow]")


if __name__ == "__main__":
    app()
