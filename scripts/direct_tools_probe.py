"""Direct MCP protocol probe for SENTINEL.

Starts ``python -m sentinel.mcp`` over stdio, performs ``tools/list``, and
prints the exact tool surface the MCP protocol exposes — the authoritative
count plus every tool name, grouped by category.

This bypasses the health check, the CLI, and doc strings: it measures the real
protocol tool listing, which is what a real MCP client (OpenCode, etc.) sees.

Usage:
    .venv/bin/python scripts/direct_tools_probe.py
"""

from __future__ import annotations

import asyncio
import os
import sys

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
VENV_PYTHON = os.path.join(PROJECT_ROOT, ".venv", "bin", "python")

CATEGORY_PREFIXES: list[tuple[str, str]] = [
    ("Engagement", "sentinel_engagement_"),
    ("Scope", "sentinel_scope_"),
    ("Recon", "sentinel_recon_"),
    ("Web", "sentinel_web_"),
    ("API", "sentinel_api_"),
    ("HTTP", "sentinel_http_request"),
    ("Orchestrated Scan", "sentinel_scan"),
    ("Asset Graph", "sentinel_graph_"),
    ("Hypothesis", "sentinel_hypothesis_"),
    ("Findings", "sentinel_finding_"),
    ("Evidence", "sentinel_evidence_"),
    ("CTF", "sentinel_ctf_"),
    ("Reporting", "sentinel_report_"),
    ("Discovery", "sentinel_tools_list"),
    ("Audit", "sentinel_audit_log"),
    ("Diagnostics", "sentinel_health_check,"),
]


def _category(tool: str) -> str:
    for label, prefix in CATEGORY_PREFIXES:
        if tool.startswith(prefix):
            return label
    return "Other"


async def main() -> int:
    sys.path.insert(0, PROJECT_ROOT)

    from mcp.client.session import ClientSession
    from mcp.client.stdio import StdioServerParameters, stdio_client

    base_dir = "/tmp/sentinel_probe_base"
    os.makedirs(base_dir, exist_ok=True)
    params = StdioServerParameters(
        command=VENV_PYTHON,
        args=["-m", "sentinel.mcp"],
        cwd=PROJECT_ROOT,
        env={"SENTINEL_BASE_DIR": base_dir},
    )

    async with stdio_client(params) as streams:
        read_stream, write_stream = streams
        async with ClientSession(read_stream, write_stream) as session:
            await asyncio.wait_for(session.initialize(), timeout=60)
            result = await asyncio.wait_for(session.list_tools(), timeout=60)
            names = sorted(t.name for t in result.tools)

    print(f"MCP_TOOLS_LIST_COUNT={len(names)}")
    by_cat: dict[str, list[str]] = {}
    for n in names:
        by_cat.setdefault(_category(n), []).append(n)
    for category in sorted(by_cat):
        print(f"[{category}] ({len(by_cat[category])})")
        for n in by_cat[category]:
            print(f"  TOOL {n}")
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))