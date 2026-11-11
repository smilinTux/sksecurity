"""MCP server: only working tools are exposed, and screen_input uses the screener."""

import asyncio
import json

from sksecurity import mcp_server


# Built at runtime so the literal never sits in the repo (secret scanners).
AWS_TEXT = "AWS_KEY=" + "AKI" + "A" + "Q3ZKXW4LMNB7R2PD"


def _tools():
    return asyncio.run(mcp_server.list_tools())


def _call(name, args):
    out = asyncio.run(mcp_server.call_tool(name, args))
    return json.loads(out[0].text)


def test_tool_set():
    assert {t.name for t in _tools()} == {"screen_input", "check_secrets"}


def test_removed_tools_unknown():
    for name in ("scan_path", "get_events", "monitor_status"):
        assert "error" in _call(name, {})


def test_check_secrets_finds_key():
    data = _call("check_secrets", {"text": AWS_TEXT})
    assert data["count"] >= 1 and data["clean"] is False


def test_screen_input_uses_email_screener():
    # A secret is not a phishing signal: if this called SecretGuard it would
    # return findings. The screener returns a verdict dict.
    data = _call("screen_input", {"text": AWS_TEXT})
    assert isinstance(data, dict) and "verdict" in data
    phish = _call("screen_input", {
        "text": "Your account is suspended. Verify your password now at http://paypa1-login.tk/verify",
        "subject": "Urgent: account suspended",
    })
    assert phish["verdict"] != "safe"
