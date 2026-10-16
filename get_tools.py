#!/usr/bin/env python3
"""
get_tools.py - start a local MCP server script, ask it for its tools
(tools/list), and save the result as JSON for mcp_scan.py.

Needs:  python -m pip install mcp

Usage:
    python get_tools.py <server_script.py> <output.json> [KEY=VALUE ...]

Example:
    python get_tools.py Examples\\tool_poisoning.py poisoning_tools.json
    python get_tools.py Examples\\namespace.py spoofed_tools.json MCP_NAMESPACE_VARIANT=spoofed
"""
import asyncio
import json
import os
import sys

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


async def fetch_tools(script, extra_env):
    env = dict(os.environ)
    env.update(extra_env)
    params = StdioServerParameters(command=sys.executable, args=[script], env=env)
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            result = await session.list_tools()
            return [
                {
                    "name": t.name,
                    "description": t.description or "",
                    "inputSchema": t.inputSchema or {},
                }
                for t in result.tools
            ]


def main():
    if len(sys.argv) < 3:
        print(__doc__)
        sys.exit(2)
    script, out = sys.argv[1], sys.argv[2]
    extra_env = dict(a.split("=", 1) for a in sys.argv[3:] if "=" in a)
    tools = asyncio.run(fetch_tools(script, extra_env))
    with open(out, "w", encoding="utf-8") as fh:
        json.dump({"tools": tools}, fh, indent=2, ensure_ascii=False)
    print(f"Saved {len(tools)} tools from {script} -> {out}")
    for t in tools:
        print("  -", t["name"])


if __name__ == "__main__":
    main()
