"""CLI entry point for SENTINEL."""

from __future__ import annotations

import asyncio
import logging
import signal
import sys
import threading
from typing import Any

import click

from sentinel import __version__
from sentinel.config import SentinelConfig
from sentinel.tools import ToolRegistry, load_adapters


@click.group()
@click.version_option(__version__, prog_name="sentinel")
@click.option("--verbose", "-v", is_flag=True, help="Enable verbose logging")
@click.option("--log-level", type=click.Choice(["debug", "info", "warning", "error"], case_sensitive=False), default="info", help="Set log level")
def main(verbose: bool, log_level: str) -> None:
    """SENTINEL — AI-Assisted Security Research Platform."""
    level = logging.DEBUG if verbose else getattr(logging, log_level.upper(), logging.INFO)
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )


@main.command()
@click.option("--host", default="127.0.0.1", help="MCP server host")
@click.option("--port", default=3000, type=int, help="MCP server port")
def serve(host: str, port: int) -> None:
    """Start MCP server (stdio or SSE transport)."""
    from sentinel.mcp import create_server
    config = SentinelConfig()
    server = create_server(config)
    try:
        server.run(transport="stdio")
    except KeyboardInterrupt:
        pass


@main.command()
@click.option("--host", default="127.0.0.1", help="Dashboard host")
@click.option("--port", default=8000, type=int, help="Dashboard port")
def dashboard(host: str, port: int) -> None:
    """Start the web dashboard."""
    try:
        import uvicorn
    except ImportError:
        click.echo("uvicorn not installed. Install with: pip install uvicorn", err=True)
        sys.exit(1)
    try:
        from sentinel.api import dashboard_app
        uvicorn.run(dashboard_app, host=host, port=port, log_level="info")
    except KeyboardInterrupt:
        pass


@main.command()
@click.option("--dashboard-host", default="127.0.0.1")
@click.option("--dashboard-port", default=8000, type=int)
@click.option("--mcp-host", default="127.0.0.1")
@click.option("--mcp-port", default=3000, type=int)
def start(dashboard_host: str, dashboard_port: int, mcp_host: str, mcp_port: int) -> None:
    """Start SENTINEL platform (dashboard + MCP server)."""
    click.echo(f"⚡ Starting SENTINEL Security Platform v{__version__}")
    click.echo(f"   Dashboard: http://{dashboard_host}:{dashboard_port}")
    click.echo(f"   MCP Server: http://{mcp_host}:{mcp_port}/sse")
    click.echo()

    # Start dashboard in a thread
    def run_dashboard() -> None:
        try:
            import uvicorn
            from sentinel.api import dashboard_app
            uvicorn.run(dashboard_app, host=dashboard_host, port=dashboard_port, log_level="warning")
        except Exception as e:
            click.echo(f"Dashboard error: {e}", err=True)

    dashboard_thread = threading.Thread(target=run_dashboard, daemon=True, name="dashboard")
    dashboard_thread.start()
    click.echo("✅ Dashboard started")

    # Start MCP server (main thread) with SSE
    try:
        import uvicorn
        from sentinel.mcp import create_server
        config = SentinelConfig()
        server = create_server(config)
        click.echo("✅ MCP server starting (SSE transport)")
        server.run(transport="sse", host=mcp_host, port=mcp_port)
    except KeyboardInterrupt:
        click.echo("\n⏹  Shutting down...")
    except Exception as e:
        click.echo(f"MCP server error: {e}", err=True)
        # Keep running with just dashboard
        click.echo("Dashboard still running. Press Ctrl+C to stop.")
        try:
            dashboard_thread.join()
        except KeyboardInterrupt:
            click.echo("\n⏹  Shutting down...")


@main.command()
def doctor() -> None:
    """Check system health and dependencies."""
    click.echo("🔍 SENTINEL System Health Check")
    click.echo("=" * 50)

    # Core
    config = SentinelConfig()
    click.echo(f"  ✅ Core: v{__version__}")

    # Tools
    registry = ToolRegistry()
    load_adapters(registry)
    tool_count = len(registry._adapters)
    click.echo(f"  ✅ Tools: {tool_count} adapters loaded")

    # External tools
    import shutil
    ext_tools = ["subfinder", "httpx", "nmap", "nuclei", "ffuf", "gobuster", "katana"]
    found = []
    missing = []
    for t in ext_tools:
        if shutil.which(t):
            found.append(t)
        else:
            missing.append(t)
    click.echo(f"  ✅ External tools: {len(found)}/{len(ext_tools)} installed")
    if missing:
        click.echo(f"     Missing: {', '.join(missing)}")

    # Playwright
    try:
        import playwright
        click.echo("  ✅ Playwright: installed")
    except ImportError:
        click.echo("  ⚠️  Playwright: not installed (pip install playwright)")

    # FastAPI
    try:
        import fastapi
        click.echo("  ✅ FastAPI: installed")
    except ImportError:
        click.echo("  ⚠️  FastAPI: not installed (pip install fastapi)")

    # SQLite
    click.echo("  ✅ Storage: SQLite")

    click.echo("=" * 50)
    click.echo("Ready to launch: sentinel start")


@main.command()
def tools() -> None:
    """List all available security tools."""
    registry = ToolRegistry()
    load_adapters(registry)

    if not registry._adapters:
        click.echo("No tools loaded.")
        return

    click.echo(f"🔧 Available Tools ({len(registry._adapters)})")
    click.echo("=" * 60)
    for name, adapter in sorted(registry._adapters.items()):
        caps = adapter.capabilities()
        cap_names = caps.capabilities if hasattr(caps, 'capabilities') else []
        click.echo(f"  {name:<20} {'[' + ', '.join(cap_names) + ']' if cap_names else ''}")


@main.command()
@click.argument("tool_name")
@click.option("--json", "as_json", is_flag=True, help="Output as JSON")
def inspect(tool_name: str, as_json: bool) -> None:
    """Inspect a specific tool's schema."""
    registry = ToolRegistry()
    load_adapters(registry)

    adapter = registry._adapters.get(tool_name)
    if not adapter:
        click.echo(f"Tool '{tool_name}' not found.", err=True)
        sys.exit(1)

    schema = adapter.input_schema()
    if as_json:
        import json
        click.echo(json.dumps(schema, indent=2))
    else:
        click.echo(f"📋 {tool_name} Input Schema")
        click.echo("=" * 40)
        props = schema.get("properties", {})
        required = schema.get("required", [])
        for name, prop in props.items():
            req = " (required)" if name in required else ""
            click.echo(f"  {name}: {prop.get('type', 'any')}{req}")
            if prop.get("description"):
                click.echo(f"    {prop['description']}")


if __name__ == "__main__":
    main()
