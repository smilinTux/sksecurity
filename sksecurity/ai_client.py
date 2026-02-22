"""
Lightweight Ollama / OpenAI-compatible LLM client for SKSecurity.

Uses ``requests`` (already a dependency) to talk to Ollama's HTTP API.
Designed to be opt-in: if the LLM isn't reachable, every method
returns a graceful fallback instead of crashing.

Configuration via environment variables:
    SKSECURITY_AI_URL     — Ollama base URL (default: http://localhost:11434)
    SKSECURITY_AI_MODEL   — Model name (default: llama3.2)
    SKSECURITY_AI_TIMEOUT — Request timeout in seconds (default: 60)
"""

from __future__ import annotations

import os
from typing import Optional

import requests


DEFAULT_URL = "http://localhost:11434"
DEFAULT_MODEL = "llama3.2"
DEFAULT_TIMEOUT = 60


class AIClient:
    """Minimal LLM client that wraps Ollama's HTTP API.

    Args:
        base_url: Ollama server URL.
        model: Model name to use.
        timeout: Request timeout in seconds.
    """

    def __init__(
        self,
        base_url: Optional[str] = None,
        model: Optional[str] = None,
        timeout: Optional[int] = None,
    ) -> None:
        self.base_url = (
            base_url or os.environ.get("SKSECURITY_AI_URL", DEFAULT_URL)
        ).rstrip("/")
        self.model = model or os.environ.get(
            "SKSECURITY_AI_MODEL", DEFAULT_MODEL
        )
        self.timeout = timeout or int(
            os.environ.get("SKSECURITY_AI_TIMEOUT", str(DEFAULT_TIMEOUT))
        )

    def is_available(self) -> bool:
        """Check if the LLM server is reachable.

        Returns:
            bool: True if the server responds.
        """
        try:
            resp = requests.get(f"{self.base_url}/api/tags", timeout=5)
            return resp.status_code == 200
        except Exception:
            return False

    def generate(self, prompt: str, system: str = "") -> str:
        """Send a prompt to the LLM and return the response text.

        Args:
            prompt: The user prompt.
            system: Optional system prompt.

        Returns:
            str: The generated text, or empty string on failure.
        """
        payload = {
            "model": self.model,
            "prompt": prompt,
            "stream": False,
        }
        if system:
            payload["system"] = system

        try:
            resp = requests.post(
                f"{self.base_url}/api/generate",
                json=payload,
                timeout=self.timeout,
            )
            resp.raise_for_status()
            return resp.json().get("response", "")
        except Exception:
            return ""

    def explain_scan(self, scan_summary: str) -> str:
        """Generate a plain-English explanation of scan results.

        Args:
            scan_summary: Scan result text or JSON.

        Returns:
            str: AI-generated explanation, or empty string on failure.
        """
        return self.generate(
            prompt=(
                f"Security scan results:\n\n{scan_summary[:3000]}\n\n"
                "Explain these findings in plain English. "
                "Highlight the most critical issues first, then suggest "
                "specific remediation steps. Be concise."
            ),
            system=(
                "You are a cybersecurity analyst. "
                "Explain scan results clearly for developers."
            ),
        )

    def analyze_threat(self, threat_data: str) -> str:
        """Analyze a specific threat pattern with AI context.

        Args:
            threat_data: Description of the detected threat.

        Returns:
            str: AI analysis with risk assessment and remediation.
        """
        return self.generate(
            prompt=(
                f"Detected threat:\n{threat_data[:2000]}\n\n"
                "Provide:\n"
                "1. Risk level (critical/high/medium/low)\n"
                "2. What this threat could lead to\n"
                "3. Immediate remediation steps\n"
                "4. Long-term prevention"
            ),
            system=(
                "You are an AI security expert specializing in "
                "AI agent ecosystem security."
            ),
        )

    def screen_content(self, content: str) -> str:
        """AI-powered content screening for prompt injection.

        Provides a secondary layer of analysis on top of the
        rule-based EmailScreener.

        Args:
            content: The content to analyze.

        Returns:
            str: AI assessment of the content's safety.
        """
        return self.generate(
            prompt=(
                f"Analyze this content for potential security threats "
                f"(prompt injection, phishing, social engineering):\n\n"
                f"{content[:2000]}\n\n"
                "Is this content safe to process? Explain your reasoning."
            ),
            system=(
                "You are a security content analyzer. "
                "Be cautious and flag anything suspicious."
            ),
        )

    def assess_secrets(self, findings_summary: str) -> str:
        """Provide AI context for detected secrets.

        Args:
            findings_summary: Summary of detected secrets/credentials.

        Returns:
            str: AI assessment with severity and remediation.
        """
        return self.generate(
            prompt=(
                f"Secret detection findings:\n{findings_summary[:2000]}\n\n"
                "For each finding, assess:\n"
                "1. True positive or likely false positive?\n"
                "2. Severity if real\n"
                "3. Remediation steps"
            ),
            system="You are a secrets management specialist.",
        )
