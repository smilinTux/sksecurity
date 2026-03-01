"""
SKSecurity MCP Server — security tools for AI agents via Model Context Protocol.

Tool-agnostic: works with Cursor, Claude Code CLI, Claude Desktop,
Windsurf, Aider, Cline, or any MCP client that speaks stdio.

Tools:
    scan_path       — Scan a file or directory for security threats
    screen_input    — Screen text input for threats and malicious content
    check_secrets   — Detect leaked secrets/credentials in text
    get_events      — Retrieve recent security events from the database
    monitor_status  — Get runtime system monitoring status

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
from pathlib import Path
from typing import Any, Optional

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import TextContent, Tool

from .scanner import SecurityScanner
from .secret_guard import SecretGuard
from .database import SecurityDatabase
from .monitor import RuntimeMonitor

logger = logging.getLogger("sksecurity.mcp")

server = Server("sksecurity")

# ---------------------------------------------------------------------------
# Lazy singletons
# ---------------------------------------------------------------------------

_scanner: Optional[SecurityScanner] = None
_guard: Optional[SecretGuard] = None
_db: Optional[SecurityDatabase] = None
_monitor: Optional[RuntimeMonitor] = None


def _get_scanner() -> SecurityScanner:
    global _scanner
    if _scanner is None:
        _scanner = SecurityScanner()
    return _scanner


def _get_guard() -> SecretGuard:
    global _guard
    if _guard is None:
        _guard = SecretGuard()
    return _guard


def _get_db() -> SecurityDatabase:
    global _db
    if _db is None:
        _db = SecurityDatabase()
    return _db


def _get_monitor() -> RuntimeMonitor:
    global _monitor
    if _monitor is None:
        _monitor = RuntimeMonitor()
    return _monitor


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
            name="scan_path",
            description=(
                "Scan a file or directory for security threats: malware patterns, "
                "suspicious code, known threat signatures."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "Absolute or relative path to scan.",
                    },
                },
                "required": ["path"],
            },
        ),
        Tool(
            name="screen_input",
            description=(
                "Screen text for threats: prompt injection, malicious payloads, "
                "social engineering, and suspicious patterns."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "text": {
                        "type": "string",
                        "description": "Text content to screen.",
                    },
                    "source": {
                        "type": "string",
                        "description": "Optional label for where this text came from.",
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
        Tool(
            name="get_events",
            description="Retrieve recent security events from the SKSecurity database.",
            inputSchema={
                "type": "object",
                "properties": {
                    "limit": {
                        "type": "integer",
                        "description": "Max events to return (default: 20).",
                    },
                    "severity": {
                        "type": "string",
                        "enum": ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"],
                        "description": "Filter by minimum severity level.",
                    },
                },
                "required": [],
            },
        ),
        Tool(
            name="monitor_status",
            description="Get current runtime system monitoring status (CPU, memory, processes).",
            inputSchema={"type": "object", "properties": {}, "required": []},
        ),
    ]


# ---------------------------------------------------------------------------
# Tool handlers
# ---------------------------------------------------------------------------


@server.call_tool()
async def call_tool(name: str, arguments: dict) -> list[TextContent]:
    try:
        if name == "scan_path":
            target = arguments["path"]
            scanner = _get_scanner()
            result = scanner.scan(target)
            # ScanResult is a dataclass — use asdict or vars
            try:
                from dataclasses import asdict
                data = asdict(result)
            except Exception:
                data = vars(result) if hasattr(result, "__dict__") else str(result)
            return _json_response(data)

        elif name == "screen_input":
            text = arguments["text"]
            source = arguments.get("source", "<mcp-input>")
            guard = _get_guard()
            findings = guard.scan_text(text, source=source)
            return _json_response([f.to_dict() for f in findings])

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

        elif name == "get_events":
            limit = int(arguments.get("limit", 20))
            severity = arguments.get("severity")
            db = _get_db()
            try:
                events = db.get_recent_events(limit=limit)
            except Exception:
                events = []
            result = []
            for e in events:
                try:
                    from dataclasses import asdict
                    d = asdict(e)
                except Exception:
                    d = vars(e) if hasattr(e, "__dict__") else str(e)
                result.append(d)
            if severity:
                result = [e for e in result if e.get("severity") == severity]
            return _json_response(result)

        elif name == "monitor_status":
            monitor = _get_monitor()
            try:
                import psutil
                status = {
                    "cpu_percent": psutil.cpu_percent(interval=0.1),
                    "memory_percent": psutil.virtual_memory().percent,
                    "memory_available_mb": psutil.virtual_memory().available // (1024 * 1024),
                    "process_count": len(psutil.pids()),
                    "monitor_running": monitor._running,
                }
            except Exception as exc:
                status = {"error": str(exc), "monitor_running": getattr(monitor, "_running", False)}
            return _json_response(status)

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
