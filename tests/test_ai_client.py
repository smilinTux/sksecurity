"""Tests for the AI client module (Ollama integration).

These tests verify the client interface without requiring a running
Ollama server. The client is designed to fail gracefully.
"""

import pytest

from sksecurity.ai_client import AIClient, DEFAULT_MODEL, DEFAULT_URL


class TestClientInit:
    """Client initialization and configuration."""

    def test_defaults(self):
        """Client uses sensible defaults."""
        client = AIClient()
        assert client.base_url == DEFAULT_URL
        assert client.model == DEFAULT_MODEL

    def test_custom_url(self):
        """Custom URL is respected."""
        client = AIClient(base_url="http://my-server:11434")
        assert client.base_url == "http://my-server:11434"

    def test_custom_model(self):
        """Custom model name is respected."""
        client = AIClient(model="mistral")
        assert client.model == "mistral"

    def test_env_vars(self, monkeypatch):
        """Environment variables configure the client."""
        monkeypatch.setenv("SKSECURITY_AI_URL", "http://env:1234")
        monkeypatch.setenv("SKSECURITY_AI_MODEL", "phi3")
        monkeypatch.setenv("SKSECURITY_AI_TIMEOUT", "30")

        client = AIClient()
        assert client.base_url == "http://env:1234"
        assert client.model == "phi3"
        assert client.timeout == 30

    def test_explicit_overrides_env(self, monkeypatch):
        """Explicit args take precedence over env vars."""
        monkeypatch.setenv("SKSECURITY_AI_MODEL", "phi3")
        client = AIClient(model="gemma2")
        assert client.model == "gemma2"


class TestAvailability:
    """Server availability checks."""

    def test_not_available_when_unreachable(self):
        """Returns False when server is not running."""
        client = AIClient(base_url="http://localhost:99999")
        assert client.is_available() is False


class TestGracefulFallback:
    """All methods fail gracefully when LLM is unreachable."""

    @pytest.fixture
    def offline_client(self):
        return AIClient(base_url="http://localhost:99999")

    def test_generate_returns_empty(self, offline_client):
        """Generate returns empty string when offline."""
        assert offline_client.generate("hello") == ""

    def test_explain_scan_returns_empty(self, offline_client):
        """Explain scan returns empty string when offline."""
        assert offline_client.explain_scan("scan results") == ""

    def test_analyze_threat_returns_empty(self, offline_client):
        """Analyze threat returns empty string when offline."""
        assert offline_client.analyze_threat("threat data") == ""

    def test_screen_content_returns_empty(self, offline_client):
        """Screen content returns empty string when offline."""
        assert offline_client.screen_content("suspicious content") == ""

    def test_assess_secrets_returns_empty(self, offline_client):
        """Assess secrets returns empty string when offline."""
        assert offline_client.assess_secrets("secret findings") == ""
