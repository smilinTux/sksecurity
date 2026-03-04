/**
 * SKSecurity — OpenClaw Plugin
 *
 * Registers agent tools that wrap the sksecurity CLI so Lumina and other
 * OpenClaw agents can run security scans, audits, and monitoring
 * as first-class tools.
 *
 * Requires: sksecurity CLI on PATH (typically via ~/.skenv/bin/sksecurity)
 */

import { execSync } from "node:child_process";
import type { OpenClawPluginApi, AnyAgentTool } from "openclaw/plugin-sdk";
import { emptyPluginConfigSchema } from "openclaw/plugin-sdk";

const SKSECURITY_BIN = process.env.SKSECURITY_BIN || "sksecurity";
const EXEC_TIMEOUT = 60_000;

function runCli(args: string): { ok: boolean; output: string } {
  try {
    const raw = execSync(`${SKSECURITY_BIN} ${args}`, {
      encoding: "utf-8",
      timeout: EXEC_TIMEOUT,
      env: {
        ...process.env,
        PATH: `${process.env.HOME}/.local/bin:${process.env.HOME}/.skenv/bin:${process.env.PATH}`,
      },
    }).trim();
    return { ok: true, output: raw };
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    return { ok: false, output: msg };
  }
}

function textResult(text: string) {
  return { content: [{ type: "text" as const, text }] };
}

function escapeShellArg(s: string): string {
  return `'${s.replace(/'/g, "'\\''")}'`;
}

// ── Tool definitions ────────────────────────────────────────────────────

function createSKSecurityScanTool() {
  return {
    name: "sksecurity_scan",
    label: "SKSecurity Scan",
    description:
      "Scan a file or directory for security vulnerabilities.",
    parameters: {
      type: "object",
      required: ["path"],
      properties: {
        path: { type: "string", description: "Path to scan." },
      },
    },
    async execute(_id: string, params: Record<string, unknown>) {
      const path = escapeShellArg(String(params.path ?? "."));
      const result = runCli(`scan ${path}`);
      return textResult(result.output);
    },
  };
}

function createSKSecurityScreenTool() {
  return {
    name: "sksecurity_screen",
    label: "SKSecurity Screen",
    description:
      "Screen input content for prompt injection, phishing attempts, and other threats.",
    parameters: {
      type: "object",
      required: ["content"],
      properties: {
        content: { type: "string", description: "Content to screen for threats." },
      },
    },
    async execute(_id: string, params: Record<string, unknown>) {
      const content = escapeShellArg(String(params.content ?? ""));
      const result = runCli(`screen ${content}`);
      return textResult(result.output);
    },
  };
}

function createSKSecuritySecretsTool() {
  return {
    name: "sksecurity_secrets",
    label: "SKSecurity Secrets",
    description:
      "Detect leaked secrets and credentials in files.",
    parameters: {
      type: "object",
      required: ["path"],
      properties: {
        path: { type: "string", description: "Path to scan for secrets." },
      },
    },
    async execute(_id: string, params: Record<string, unknown>) {
      const path = escapeShellArg(String(params.path ?? "."));
      const result = runCli(`guard scan ${path}`);
      return textResult(result.output);
    },
  };
}

function createSKSecurityEventsTool() {
  return {
    name: "sksecurity_events",
    label: "SKSecurity Events",
    description: "Show recent security events and alerts.",
    parameters: { type: "object", properties: {} },
    async execute() {
      const result = runCli("events");
      return textResult(result.output);
    },
  };
}

function createSKSecurityStatusTool() {
  return {
    name: "sksecurity_status",
    label: "SKSecurity Status",
    description: "Show security system operational status.",
    parameters: { type: "object", properties: {} },
    async execute() {
      const result = runCli("status");
      return textResult(result.output);
    },
  };
}

function createSKSecurityAuditTool() {
  return {
    name: "sksecurity_audit",
    label: "SKSecurity Audit",
    description: "Run a full security audit across the workspace.",
    parameters: { type: "object", properties: {} },
    async execute() {
      const result = runCli("audit");
      return textResult(result.output);
    },
  };
}

function createSKSecurityMonitorTool() {
  return {
    name: "sksecurity_monitor",
    label: "SKSecurity Monitor",
    description: "Start runtime security monitoring on a path.",
    parameters: {
      type: "object",
      required: ["path"],
      properties: {
        path: { type: "string", description: "Path to monitor." },
      },
    },
    async execute(_id: string, params: Record<string, unknown>) {
      const path = escapeShellArg(String(params.path ?? "."));
      const result = runCli(`monitor ${path}`);
      return textResult(result.output);
    },
  };
}

// ── Plugin registration ─────────────────────────────────────────────────

const sksecurityPlugin = {
  id: "sksecurity",
  name: "SKSecurity",
  description:
    "Security operations — vulnerability scanning, secret detection, prompt screening, auditing, and monitoring.",
  configSchema: emptyPluginConfigSchema(),

  register(api: OpenClawPluginApi) {
    const tools = [
      createSKSecurityScanTool(),
      createSKSecurityScreenTool(),
      createSKSecuritySecretsTool(),
      createSKSecurityEventsTool(),
      createSKSecurityStatusTool(),
      createSKSecurityAuditTool(),
      createSKSecurityMonitorTool(),
    ];

    for (const tool of tools) {
      api.registerTool(tool as unknown as AnyAgentTool, {
        names: [tool.name],
        optional: true,
      });
    }

    api.registerCommand({
      name: "sksecurity",
      description: "Run sksecurity CLI commands. Usage: /sksecurity <subcommand> [args]",
      acceptsArgs: true,
      handler: async (ctx) => {
        const args = ctx.args?.trim() ?? "status";
        const result = runCli(args);
        return { text: result.output };
      },
    });

    api.logger.info?.("SKSecurity plugin registered (7 tools + /sksecurity command)");
  },
};

export default sksecurityPlugin;
