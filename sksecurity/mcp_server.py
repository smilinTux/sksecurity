"""
SKSecurity MCP Server - security tools for AI agents via Model Context Protocol.

Tool-agnostic: works with Cursor, Claude Code CLI, Claude Desktop,
Windsurf, Aider, Cline, or any MCP client that speaks stdio.

Tools:
    screen_input    - Screen text for phishing / injection heuristics (EmailScreener)
    check_secrets   - Detect leaked secrets/credentials in text (SecretGuard)

Invocation:
    python -m sksecurity.mcp_server
    sksecurity-mcp

Client configuration (Cursor / Claude Desktop / Claude Code CLI):
    {"mcpServers": {"sksecurity": {
        "command": "sksecurity-mcp"}}}
"""

from __future__ import annotations

import asyncio
import json
import logging
from typing import Any, Optional

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import TextContent, Tool

from .email_screener import EmailScreener
from .secret_guard import SecretGuard

logger = logging.getLogger("sksecurity.mcp")

server = Server("sksecurity")

# ---------------------------------------------------------------------------
# Lazy singletons
# ---------------------------------------------------------------------------

_guard: Optional[SecretGuard] = None
_screener: Optional[EmailScreener] = None


def _get_guard() -> SecretGuard:
    global _guard
    if _guard is None:
        _guard = SecretGuard()
    return _guard


def _get_screener() -> EmailScreener:
    global _screener
    if _screener is None:
        _screener = EmailScreener()
    return _screener


# ---------------------------------------------------------------------------
# Response helpers
# ---------------------------------------------------------------------------


def _json_response(data: Any) -> list[TextContent]:
    return [TextContent(type="text", text=json.dumps(data, indent=2, default=str))]


def _error_response(message: str) -> list[TextContent]:
    return [TextContent(type="text", text=json.dumps({"error": message}))]


# ---------------------------------------------------------------------------
# Tool definitions
# ---------------------------------------------------------------------------


@server.list_tools()
async def list_tools() -> list[Tool]:
    return [
        Tool(
            name="screen_input",
            description=(
                "Screen text with regex heuristics for phishing, prompt injection and "
                "social engineering. Text-only and shallow: a SAFE verdict is not a "
                "guarantee."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "text": {
                        "type": "string",
                        "description": "Text content to screen.",
                    },
                    "sender": {
                        "type": "string",
                        "description": "Optional sender address (email screening).",
                    },
                    "subject": {
                        "type": "string",
                        "description": "Optional subject line.",
                    },
                },
                "required": ["text"],
            },
        ),
        Tool(
            name="check_secrets",
            description=(
                "Detect leaked secrets and credentials in text: API keys, tokens, "
                "private keys, passwords, and other sensitive data."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "text": {
                        "type": "string",
                        "description": "Text to scan for secrets.",
                    },
                    "source": {
                        "type": "string",
                        "description": "Optional label for the source of this text.",
                    },
                },
                "required": ["text"],
            },
        ),
    ]


# ---------------------------------------------------------------------------
# Tool handlers
# ---------------------------------------------------------------------------


@server.call_tool()
async def call_tool(name: str, arguments: dict) -> list[TextContent]:
    try:
        if name == "screen_input":
            text = arguments["text"]
            result = _get_screener().screen(
                text,
                sender=arguments.get("sender"),
                subject=arguments.get("subject"),
            )
            return _json_response(result.to_dict())

        elif name == "check_secrets":
            text = arguments["text"]
            source = arguments.get("source", "<mcp-input>")
            guard = _get_guard()
            findings = guard.scan_text(text, source=source)
            return _json_response(
                {
                    "findings": [f.to_dict() for f in findings],
                    "count": len(findings),
                    "clean": len(findings) == 0,
                }
            )

        else:
            return _error_response(f"Unknown tool: {name}")

    except Exception as exc:
        logger.exception("Tool %s failed", name)
        return _error_response(str(exc))


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main() -> None:
    """Run the SKSecurity MCP server on stdio transport."""
    logging.basicConfig(level=logging.WARNING, format="%(name)s: %(message)s")
    asyncio.run(_run_server())


async def _run_server() -> None:
    """Async entry point for the stdio MCP server."""
    async with stdio_server() as (read_stream, write_stream):
        await server.run(read_stream, write_stream, server.create_initialization_options())


if __name__ == "__main__":
    main()
