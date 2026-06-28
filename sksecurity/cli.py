#!/usr/bin/env python3
"""
SKSecurity Enterprise Command Line Interface
Main entry point for all security operations
"""

import os
import sys
import click
import json
from datetime import datetime
from pathlib import Path
from typing import Optional

from . import __version__, BANNER
from .ai_client import AIClient
from .scanner import SecurityScanner
from .dashboard import DashboardServer
from .intelligence import ThreatIntelligence
from .database import SecurityDatabase
from .config import SecurityConfig
from .monitor import SecurityMonitor
from .quarantine import QuarantineManager
from .email_screener import EmailScreener
from .secret_guard import SecretGuard, GuardResult
from .honest_claims import HonestClaimsScanner
from .pdf_report import generate_audit_pdf

@click.group()
@click.version_option(__version__, prog_name="sksecurity")
@click.option('--config', '-c', type=click.Path(), help='Configuration file path')
@click.option('--verbose', '-v', is_flag=True, help='Verbose output')
@click.option('--ai', 'use_ai', is_flag=True, envvar='SKSECURITY_AI', help='Enable AI-powered analysis (requires Ollama)')
@click.option('--ai-model', envvar='SKSECURITY_AI_MODEL', default=None, help='Ollama model name (default: llama3.2)')
@click.option('--ai-url', envvar='SKSECURITY_AI_URL', default=None, help='Ollama server URL')
@click.pass_context
def cli(ctx, config, verbose, use_ai, ai_model, ai_url):
    """🛡️ SKSecurity Enterprise - AI Agent Security Platform

    Enterprise-grade security for AI agent ecosystems.

    Use --ai to enable AI-powered analysis (scan explanations,
    threat assessment, content screening). Requires Ollama.
    """
    ctx.ensure_object(dict)
    ctx.obj['verbose'] = verbose
    ctx.obj['config'] = config or SecurityConfig.get_default_config_path()

    if use_ai:
        ai = AIClient(base_url=ai_url, model=ai_model)
        if ai.is_available():
            ctx.obj['ai'] = ai
            if verbose:
                click.echo(f"AI enabled: {ai.model} @ {ai.base_url}")
        else:
            click.echo(
                f"Warning: AI requested but Ollama not reachable at {ai.base_url}",
                err=True,
            )
            ctx.obj['ai'] = None
    else:
        ctx.obj['ai'] = None

@cli.command()
@click.argument('path', type=click.Path(exists=True))
@click.option('--format', 'output_format', default='text', type=click.Choice(['text', 'json', 'yaml']))
@click.option('--threshold', '-t', default=80, type=int, help='Risk threshold for quarantine')
@click.option('--quarantine/--no-quarantine', default=True, help='Auto-quarantine threats')
@click.option('--export', type=click.Path(), help='Export results to file')
@click.pass_context
def scan(ctx, path, output_format, threshold, quarantine, export):
    """Scan AI agent or skill for security vulnerabilities.
    
    Examples:
        sksecurity scan ./my-ai-agent
        sksecurity scan ./suspicious-skill --format json
        sksecurity scan ./agent-code --threshold 60 --no-quarantine
    """
    config = SecurityConfig.load(ctx.obj['config'])
    scanner = SecurityScanner(config=config)
    
    if ctx.obj['verbose']:
        click.echo("🔍 Starting security scan...")
        click.echo(f"Target: {path}")
        click.echo(f"Threshold: {threshold}")
    
    # Perform scan
    result = scanner.scan(Path(path))
    
    # Auto-quarantine if enabled and threshold exceeded
    if quarantine and result.risk_score >= threshold:
        quarantine_mgr = QuarantineManager(config=config)
        quarantine_record = quarantine_mgr.quarantine(Path(path), result)
        result.quarantined = True
        result.quarantine_path = quarantine_record.quarantine_path
    
    # Format output
    if output_format == 'json':
        output = result.to_json()
    elif output_format == 'yaml':
        output = result.to_yaml()
    else:
        output = result.format_report()
    
    # Export to file if specified
    if export:
        with open(export, 'w') as f:
            f.write(output)
        click.echo(f"Results exported to: {export}")
    else:
        click.echo(output)

    ai = ctx.obj.get('ai')
    if ai and result.risk_score > 0:
        explanation = ai.explain_scan(output[:3000])
        if explanation:
            click.echo("\n🤖 AI Analysis:")
            click.echo(explanation)

    sys.exit(1 if result.risk_score >= threshold else 0)

@cli.command()
@click.option('--host', '-h', default='localhost', help='Dashboard host')
@click.option('--port', '-p', default=8888, type=int, help='Dashboard port')
@click.option('--auth/--no-auth', default=False, help='Enable authentication')
@click.option('--ssl/--no-ssl', default=False, help='Enable SSL')
@click.option('--background', '-b', is_flag=True, help='Run in background')
@click.pass_context
def dashboard(ctx, host, port, auth, ssl, background):
    """Launch security operations center dashboard.
    
    Opens a web-based security dashboard with real-time monitoring,
    threat visualization, and security metrics.
    
    Examples:
        sksecurity dashboard
        sksecurity dashboard --port 9999 --auth
        sksecurity dashboard --host 0.0.0.0 --ssl
    """
    config = SecurityConfig.load(ctx.obj['config'])
    server = DashboardServer(
        host=host,
        port=port, 
        auth_enabled=auth,
        ssl_enabled=ssl,
        config=config
    )
    
    click.echo(f"🛡️ Starting SKSecurity Dashboard")
    click.echo(f"📍 URL: {'https' if ssl else 'http'}://{host}:{port}")
    if auth:
        click.echo("🔐 Authentication: Enabled")
    
    if background:
        click.echo("🔄 Running in background...")
        server.run_background()
    else:
        click.echo("Press Ctrl+C to stop")
        try:
            server.run()
        except KeyboardInterrupt:
            click.echo("\n🛑 Dashboard stopped")

@cli.command()
@click.option('--sources', default='all', help='Threat sources to update (comma-separated)')
@click.option('--force', is_flag=True, help='Force update even if recent')
@click.pass_context  
def update(ctx, sources, force):
    """Update threat intelligence from all configured sources.
    
    Fetches the latest security threats from multiple sources including
    Moltbook, NVD, GitHub Security Advisories, and community feeds.
    
    Examples:
        sksecurity update
        sksecurity update --sources moltbook,nvd
        sksecurity update --force
    """
    config = SecurityConfig.load(ctx.obj['config'])
    intel = ThreatIntelligence(config=config)
    
    if ctx.obj['verbose']:
        click.echo("🧠 Updating threat intelligence...")
    
    # Parse sources
    if sources == 'all':
        source_list = None  # Use all configured sources
    else:
        source_list = [s.strip() for s in sources.split(',')]
    
    # Update threat intelligence
    updated_count = intel.update(sources=source_list, force=force)
    
    click.echo(f"✅ Updated {updated_count} threat patterns")
    
    if ctx.obj['verbose']:
        intel_status = intel.get_status()
        click.echo(f"Total patterns: {intel_status['total_patterns']}")
        click.echo(f"Last update: {intel_status['last_update']}")

@cli.command()
@click.argument('path', type=click.Path(exists=True))
@click.option('--continuous', is_flag=True, help='Continuous monitoring')
@click.option('--alerts/--no-alerts', default=True, help='Enable alerts')
@click.option('--duration', type=int, help='Monitoring duration in seconds')
@click.pass_context
def monitor(ctx, path, continuous, alerts, duration):
    """Monitor AI agent execution for security threats.
    
    Provides real-time monitoring of AI agent behavior, detecting
    suspicious activities, unauthorized access, and threat patterns.
    
    Examples:
        sksecurity monitor ./my-agent
        sksecurity monitor ./agent-dir --continuous
        sksecurity monitor ./agent --duration 3600
    """
    config = SecurityConfig.load(ctx.obj['config'])
    monitor = SecurityMonitor(config=config)
    
    click.echo(f"🔍 Starting security monitoring: {path}")
    if continuous:
        click.echo("⏰ Continuous monitoring enabled (Ctrl+C to stop)")
    elif duration:
        click.echo(f"⏱️ Monitoring for {duration} seconds")
    
    try:
        if continuous:
            monitor.monitor_continuous(Path(path), alerts=alerts)
        else:
            monitor.monitor_duration(Path(path), duration=duration, alerts=alerts)
    except KeyboardInterrupt:
        click.echo("\n🛑 Monitoring stopped")

@cli.command()
@click.option('--framework', type=click.Choice(['openclaw', 'autogpt', 'langchain', 'generic']))
@click.option('--config-only', is_flag=True, help='Only create configuration')
@click.pass_context
def init(ctx, framework, config_only):
    """Initialize SKSecurity in current directory.
    
    Sets up configuration, creates security database, and prepares
    the environment for AI agent security monitoring.
    
    Examples:
        sksecurity init
        sksecurity init --framework openclaw
        sksecurity init --config-only
    """
    if not framework:
        # Auto-detect framework
        framework = detect_framework()
        if framework:
            click.echo(f"🔍 Detected framework: {framework}")
        else:
            framework = 'generic'
            click.echo("🔧 Using generic configuration")
    
    config_path = SecurityConfig.create_default_config(framework=framework)
    click.echo(f"⚙️ Created configuration: {config_path}")
    
    if not config_only:
        # Initialize database
        config = SecurityConfig.load(config_path)
        db = SecurityDatabase(config=config)
        db.initialize()
        click.echo("🗃️ Initialized security database")
        
        # Update threat intelligence
        intel = ThreatIntelligence(config=config)
        try:
            updated = intel.update()
            click.echo(f"🧠 Updated {updated} threat patterns")
        except Exception as e:
            click.echo(f"⚠️ Threat intelligence update failed: {e}")
    
    click.echo("✅ SKSecurity initialization complete")

@cli.command()
@click.option('--severity', type=click.Choice(['all', 'critical', 'high', 'medium', 'low']), default='all')
@click.option('--limit', type=int, default=20, help='Maximum number of items to show')
@click.pass_context
def quarantine(ctx, severity, limit):
    """Manage quarantined threats and security incidents.
    
    Lists, inspects, and manages items that have been automatically
    quarantined due to security threats.
    
    Examples:
        sksecurity quarantine
        sksecurity quarantine --severity critical
        sksecurity quarantine --limit 10
    """
    config = SecurityConfig.load(ctx.obj['config'])
    quarantine_mgr = QuarantineManager(config=config)
    
    records = quarantine_mgr.list_quarantine(severity=severity, limit=limit)
    
    if not records:
        click.echo("📁 No items in quarantine")
        return
    
    click.echo(f"🔒 Quarantine ({len(records)} items):")
    click.echo("=" * 60)
    
    for record in records:
        click.echo(f"📂 {record.original_path}")
        click.echo(f"   Risk Score: {record.risk_score}")
        click.echo(f"   Severity: {record.severity}")
        click.echo(f"   Date: {record.timestamp}")
        click.echo(f"   Location: {record.quarantine_path}")
        click.echo()

@cli.command()
@click.option('--export', type=click.Path(), help='Export audit report')
@click.option('--format', 'output_format', default='text', type=click.Choice(['text', 'json', 'pdf']))
@click.pass_context
def audit(ctx, export, output_format):
    """Run comprehensive security audit and generate report.
    
    Performs a complete security assessment including threat intelligence
    status, system security, quarantine review, and compliance checks.
    
    Examples:
        sksecurity audit
        sksecurity audit --export audit-report.json --format json
        sksecurity audit --format pdf --export security-audit.pdf
    """
    config = SecurityConfig.load(ctx.obj['config'])
    
    click.echo("🛡️ Running comprehensive security audit...")

    # Collect audit data
    audit_data = {
        'timestamp': datetime.now().isoformat(),
        'version': __version__,
        'threat_intelligence': ThreatIntelligence(config=config).get_status(),
        'quarantine': QuarantineManager(config=config).get_stats(),
        'database': SecurityDatabase(config=config).get_stats(),
        'configuration': config.get_summary()
    }

    # Format output
    if output_format == 'json':
        output = json.dumps(audit_data, indent=2)
        if export:
            with open(export, 'w') as f:
                f.write(output)
            click.echo(f"📊 Audit report exported: {export}")
        else:
            click.echo(output)
    elif output_format == 'pdf':
        pdf_bytes = generate_audit_pdf(audit_data)
        out_path = export or 'security-audit.pdf'
        with open(out_path, 'wb') as f:
            f.write(pdf_bytes)
        click.echo(f"📄 PDF audit report written: {out_path}")
    else:
        output = format_audit_report(audit_data)
        if export:
            with open(export, 'w') as f:
                f.write(output)
            click.echo(f"📊 Audit report exported: {export}")
        else:
            click.echo(output)

@cli.command()
@click.pass_context
def status(ctx):
    """Show SKSecurity system status and health.
    
    Displays current security status, active monitoring, threat intelligence
    status, and overall system health.
    """
    config = SecurityConfig.load(ctx.obj['config'])
    
    click.echo(BANNER)
    click.echo("📊 System Status")
    click.echo("=" * 30)
    
    # Threat intelligence status
    intel = ThreatIntelligence(config=config)
    intel_status = intel.get_status()
    click.echo(f"🧠 Threat Intelligence: {intel_status['total_patterns']} patterns")
    click.echo(f"   Last Update: {intel_status['last_update']}")
    
    # Database status  
    db = SecurityDatabase(config=config)
    db_stats = db.get_stats()
    click.echo(f"🗃️ Security Database: {db_stats['total_events']} events")
    
    # Quarantine status
    quarantine_mgr = QuarantineManager(config=config)
    quarantine_stats = quarantine_mgr.get_stats()
    click.echo(f"🔒 Quarantine: {quarantine_stats['total_items']} items")
    
    # Configuration
    click.echo(f"⚙️ Configuration: {ctx.obj['config']}")
    click.echo(f"🛡️ Auto-quarantine: {'Enabled' if config.get('security.auto_quarantine', True) else 'Disabled'}")

    # PQC crypto posture self-report — LIVE (reflects the operator's real
    # groups/stores post confidentiality cut-over; honest mixed state).
    from .pqc_report import build_live_report
    pqc = build_live_report()
    sm = pqc["summary"]
    click.echo(
        f"🔐 PQC posture: {sm['quantum_resistant']}/{sm['total_surfaces']} "
        f"quantum-resistant ({sm['classical']} classical, {sm['symmetric']} symmetric) "
        f"— {pqc['phase']}"
    )
    gb = pqc.get("group_breakdown")
    if gb and gb["total"]:
        click.echo(
            f"   group-key: hybrid-pq for {gb['hybrid']}/{gb['total']} groups "
            f"({gb['classical']} classical)"
        )
    click.echo("   Run 'sksecurity pqc-report' for the per-surface breakdown.")

    click.echo("\n✅ SKSecurity is operational")


@cli.command(name="pqc-report")
@click.option('--format', 'output_format', default='text',
              type=click.Choice(['text', 'json']))
@click.option('--static', 'static', is_flag=True, default=False,
              help="Show the model-DEFAULT posture instead of the live fleet state.")
@click.option('--project', 'project', default=None,
              help="Scope the report to ONE project's owned surfaces "
                   "(skchat / skcomms / capauth / sksecurity).")
@click.pass_context
def pqc_report(ctx, output_format, static, project):
    """Show the per-surface PQC (quantum-resistance) self-report.

    Enumerates, per security surface (identity, envelope signature, group key,
    at-rest), the cipher suite in use + its quantum-resistance status + FIPS
    refs. This is the evidence backing any quantum-resistance claim.

    By default this reflects REALITY: the operator's actual groups + at-rest
    store post confidentiality cut-over (a surface is hybrid-pq only when truly
    migrated/negotiated; mixed state is reported honestly). Pass --static for the
    model-default posture (what NEW objects default to, independent of live data).

    Pass --project skchat|skcomms|capauth|sksecurity to scope the report to a
    single project's owned surfaces ("what is MY project's PQC posture?").
    """
    from .pqc_report import (
        build_live_report, build_report, format_report,
        build_project_report, format_project_report, known_projects,
    )
    if project:
        proj = project.lower()
        if proj not in known_projects():
            raise click.BadParameter(
                f"unknown project {project!r}; known: {', '.join(known_projects())}"
            )
        rpt = build_project_report(proj, live=not static)
        if output_format == 'json':
            click.echo(json.dumps(rpt, indent=2))
        else:
            click.echo(format_project_report(rpt))
        return
    rpt = build_report() if static else build_live_report()
    if output_format == 'json':
        click.echo(json.dumps(rpt, indent=2))
    else:
        click.echo(format_report(rpt))


@cli.command(name="pqc-stacks")
@click.option('--format', 'output_format', default='text',
              type=click.Choice(['text', 'json']))
@click.pass_context
def pqc_stacks(ctx, output_format):
    """Itemize EACH SKStacks v2 service with its honest crypto posture.

    Lists every service/component declared in the SKStacks v2 descriptors
    (transport TLS / at-rest / identity), marking classical / symmetric / n/a
    plainly and UNKNOWN services as 'unaudited' (never assumed-secure). No
    stack service is quantum-resistant (transport is classical TLS).
    """
    from .pqc_stacks import build_stacks_report, format_stacks_report
    try:
        rpt = build_stacks_report()
    except FileNotFoundError as exc:
        raise click.ClickException(str(exc))
    if output_format == 'json':
        click.echo(json.dumps(rpt, indent=2))
    else:
        click.echo(format_stacks_report(rpt))


@cli.command(name="pqc-snapshot")
@click.option('--label', default='', help="Human label for this snapshot.")
@click.option('--static', 'static', is_flag=True, default=False,
              help="Snapshot the model-DEFAULT posture instead of the live fleet.")
@click.option('--seed', is_flag=True, default=False,
              help="Seed the JSON ledger with the #1-6 milestone history first "
                   "(idempotent).")
@click.option('--format', 'output_format', default='text',
              type=click.Choice(['text', 'json']))
@click.pass_context
def pqc_snapshot(ctx, label, static, seed, output_format):
    """Append a DATED snapshot of the current PQC posture to the JSON ledger.

    Writes docs/pqc-progression.json (the machine-readable companion to the
    narrative .md): per-surface + per-group counts at this moment, so the
    historical current-vs-enabled trend is reconstructable from data over time.
    """
    from .pqc_report import append_snapshot, seed_ledger, LEDGER_JSON
    if seed:
        seed_ledger()
    snap = append_snapshot(label=label, live=not static)
    if output_format == 'json':
        click.echo(json.dumps(snap, indent=2))
    else:
        click.echo(f"📌 Appended PQC snapshot {snap['date']} → {LEDGER_JSON}")
        sc = snap.get("status_counts", {})
        click.echo("   status_counts: " + ", ".join(
            f"{k}={v}" for k, v in sorted(sc.items())))
        gb = snap.get("group_breakdown")
        if gb and gb.get("total"):
            click.echo(f"   group-key: {gb['hybrid']}/{gb['total']} hybrid")


@cli.command(name="pqc-dashboard")
@click.option('--format', 'output_format', default='text',
              type=click.Choice(['text', 'json']))
@click.option('--static', 'static', is_flag=True, default=False,
              help="Use the model-DEFAULT posture instead of the live fleet.")
@click.option('--no-stacks', is_flag=True, default=False,
              help="Skip the SKStacks per-service section.")
@click.pass_context
def pqc_dashboard(ctx, output_format, static, no_stacks):
    """One view of the WHOLE ecosystem's quantum-resistance posture.

    Aggregate + per-project + per-service (SKStacks) + the historical trend
    (read from docs/pqc-progression.json). The single command to see how many
    surfaces/services/groups are classical vs hybrid-pq and how that has moved.
    """
    from .pqc_report import build_dashboard, format_dashboard
    dash = build_dashboard(live=not static, include_stacks=not no_stacks)
    if output_format == 'json':
        click.echo(json.dumps(dash, indent=2))
    else:
        click.echo(format_dashboard(dash))

@cli.command(name="pqc-posture")
@click.option('--format', 'output_format', default='text',
              type=click.Choice(['text', 'json']))
@click.option('--static', 'static', is_flag=True, default=False,
              help="Static honest-default coverage instead of live operator enrichment.")
@click.pass_context
def pqc_posture(ctx, output_format, static):
    """PQC POSTURE / coverage table — per surface: hybrid-pq / gated / classical.

    Scans the six security surfaces of the sovereign-comms ecosystem (DM ratchet,
    group, metadata, identity/signatures, at-rest, transport) and reports, for
    each, whether hybrid-PQ is the DEFAULT (hybrid-pq), merely AVAILABLE/opt-in/
    negotiated (gated), or ABSENT (classical). Grounded in the REAL wire-tags
    (pqdr1, kem_suite/x25519-mlkem768, aqid:+pqroute1, sig_suite, wrap_suite, the
    classical channel underlay) — never an out-of-band assumption.

    Live mode (default) up-rates group/at-rest from the operator's real objects
    only when the evidence is unambiguous; --static shows the honest default.
    Honest claims only — hybrid = either-leg (FIPS 203 / FIPS 204); never
    'quantum-proof' or whole-system post-quantum.
    """
    from .pqc_posture import build_posture, format_posture
    rpt = build_posture(live=not static)
    if output_format == 'json':
        click.echo(json.dumps(rpt, indent=2))
    else:
        click.echo(format_posture(rpt))


@cli.command()
@click.argument('content', required=False)
@click.option('--file', '-f', type=click.Path(exists=True), help='Read content from file')
@click.option('--sender', '-s', help='Email sender address')
@click.option('--subject', help='Email subject line')
@click.option('--format', 'output_format', default='text', type=click.Choice(['text', 'json']))
@click.pass_context
def screen(ctx, content, file, sender, subject, output_format):
    """Screen email or input content for threats before AI processing.

    Detects prompt injection, phishing, credential leaks, and malicious links
    in content before it reaches the AI model.

    Examples:
        sksecurity screen "Hello, please verify your account"
        sksecurity screen -f email.txt --sender user@example.com
        echo "some content" | sksecurity screen
    """
    if file:
        with open(file, 'r') as f:
            content = f.read()
    elif not content:
        if not sys.stdin.isatty():
            content = sys.stdin.read()
        else:
            click.echo("Error: Provide content as argument, --file, or via stdin")
            sys.exit(1)

    screener = EmailScreener()
    result = screener.screen(content, sender=sender, subject=subject)

    if output_format == 'json':
        click.echo(json.dumps(result.to_dict(), indent=2))
    else:
        click.echo(result.format_report())

    ai = ctx.obj.get('ai')
    if ai and not result.is_safe:
        assessment = ai.screen_content(content[:2000])
        if assessment:
            click.echo("\n🤖 AI Assessment:")
            click.echo(assessment)

    sys.exit(0 if result.is_safe else 1)


@cli.group()
def guard():
    """Secret leak prevention — detect and block credential leaks.

    Scans files, directories, and git staging areas for API keys,
    tokens, passwords, and other secrets.
    """
    pass


@guard.command(name='scan')
@click.argument('path', type=click.Path(exists=True), default='.')
@click.option('--format', 'output_format', default='text', type=click.Choice(['text', 'json']))
@click.pass_context
def guard_scan(ctx, path, output_format):
    """Scan files or directories for secrets and credentials.

    Examples:
        sksecurity guard scan .
        sksecurity guard scan ./src --format json
        sksecurity guard scan config.py
    """
    target = Path(path)
    secret_guard = SecretGuard()

    if target.is_file():
        findings = secret_guard.scan_file(target)
        result = GuardResult(target=str(target), findings=findings, files_scanned=1)
    else:
        result = secret_guard.scan_directory(target)

    if output_format == 'json':
        click.echo(json.dumps(result.to_dict(), indent=2))
    else:
        click.echo(result.format_report())

    ai = ctx.obj.get('ai')
    if ai and result.has_secrets:
        assessment = ai.assess_secrets(result.format_report()[:2000])
        if assessment:
            click.echo("\n🤖 AI Assessment:")
            click.echo(assessment)

    sys.exit(1 if result.has_secrets else 0)


@guard.command(name='staged')
@click.option('--format', 'output_format', default='text', type=click.Choice(['text', 'json']))
@click.pass_context
def guard_staged(ctx, output_format):
    """Scan git staged files for secrets (what would be committed).

    Examples:
        sksecurity guard staged
        sksecurity guard staged --format json
    """
    secret_guard = SecretGuard()
    result = secret_guard.scan_git_staged()

    if output_format == 'json':
        click.echo(json.dumps(result.to_dict(), indent=2))
    else:
        click.echo(result.format_report())

    sys.exit(1 if result.has_secrets else 0)


@guard.command(name='install')
@click.option('--repo', type=click.Path(), default='.', help='Git repository path')
@click.pass_context
def guard_install(ctx, repo):
    """Install git pre-commit hook to block secrets from being committed.

    Examples:
        sksecurity guard install
        sksecurity guard install --repo /path/to/repo
    """
    secret_guard = SecretGuard()
    try:
        hook_path = secret_guard.install_pre_commit_hook(Path(repo))
        click.echo(f"✅ Pre-commit hook installed: {hook_path}")
        click.echo("   Commits with secrets will now be automatically blocked.")
    except Exception as e:
        click.echo(f"❌ Failed to install hook: {e}", err=True)
        sys.exit(1)


@guard.command(name='text')
@click.argument('text')
@click.pass_context
def guard_text(ctx, text):
    """Scan a text string for secrets (useful for testing).

    Examples:
        sksecurity guard text "my_api_key=sk-abc123456789012345678901234567890123"
    """
    secret_guard = SecretGuard()
    findings = secret_guard.scan_text(text)

    if not findings:
        click.echo("✅ No secrets detected.")
    else:
        click.echo(f"🚨 Found {len(findings)} secret(s):")
        for finding in findings:
            click.echo(f"  🔴 {finding.secret_type}: {finding.redacted_text}")
            click.echo(f"     {finding.remediation}")

    sys.exit(1 if findings else 0)


def detect_framework():
    """Auto-detect AI framework in current directory."""
    # Check for OpenClaw
    if (Path.home() / '.openclaw' / 'openclaw.json').exists():
        return 'openclaw'
    if Path('openclaw.json').exists():
        return 'openclaw'
    
    # Check for AutoGPT
    if Path('autogpt').is_dir():
        return 'autogpt'
    
    # Check for LangChain
    if Path('langchain').is_dir():
        return 'langchain'
    
    return None

def format_audit_report(data):
    """Format audit data as text report."""
    report = f"""
🛡️ SKSecurity Enterprise Security Audit Report
===============================================
Generated: {data['timestamp']}
Version: {data['version']}

📊 Threat Intelligence Status:
  Total Patterns: {data['threat_intelligence']['total_patterns']}
  Last Update: {data['threat_intelligence']['last_update']}
  Sources: {len(data['threat_intelligence']['sources'])}

🔒 Quarantine Status:
  Total Items: {data['quarantine']['total_items']}
  Critical: {data['quarantine']['critical_count']}
  High: {data['quarantine']['high_count']}

🗃️ Security Database:
  Total Events: {data['database']['total_events']}
  Recent Alerts: {data['database']['recent_alerts']}

⚙️ Configuration Summary:
  Auto-quarantine: {data['configuration']['auto_quarantine']}
  Risk Threshold: {data['configuration']['risk_threshold']}
  Dashboard Port: {data['configuration']['dashboard_port']}

🎯 Overall Status: OPERATIONAL
"""
    return report

@cli.group()
def claims():
    """Honest-claims gate — block forbidden security overclaims.

    Scans docs, code, and comments for "quantum-proof", "quantum-safe",
    "unbreakable", "uncrackable", "100% secure", and "military-grade"
    (as a security claim). Honest negations ("never quantum-proof") and
    quoted/meta references are allowed. Exits non-zero on a real violation.
    """
    pass


@claims.command(name='scan')
@click.argument('path', type=click.Path(exists=True), default='.')
@click.option('--format', 'output_format', default='text',
              type=click.Choice(['text', 'json']))
@click.option('--allowlist-file', type=click.Path(), default=None,
              help='Path to an allowlist file (default: <path>/.honestclaims-allow)')
def claims_scan(path, output_format, allowlist_file):
    """Scan a file or directory for forbidden security overclaims.

    Examples:
        sksecurity claims scan .
        sksecurity claims scan README.md
        sksecurity claims scan ./docs --format json
    """
    target = Path(path)

    allow = Path(allowlist_file) if allowlist_file else None
    if allow is None:
        default_allow = (target if target.is_dir() else target.parent) / ".honestclaims-allow"
        if default_allow.exists():
            allow = default_allow

    scanner = HonestClaimsScanner(allowlist_file=allow)
    result = scanner.scan_path(target)

    if output_format == 'json':
        click.echo(json.dumps(result.to_dict(), indent=2))
    else:
        click.echo(result.format_report())

    sys.exit(1 if result.has_violations else 0)


@claims.command(name='text')
@click.argument('text')
def claims_text(text):
    """Scan a single string for overclaims (handy for testing).

    Examples:
        sksecurity claims text "our protocol is quantum-proof"
        sksecurity claims text "we never say quantum-proof"
    """
    findings = HonestClaimsScanner().scan_text(text)
    if not findings:
        click.echo("✅ No forbidden overclaims. Claims match the math.")
    else:
        click.echo(f"🚨 Found {len(findings)} overclaim(s):")
        for f in findings:
            click.echo(f"  🔴 {f.claim}: {f.matched_text}")
            click.echo(f"     Say: {f.suggestion}")
    sys.exit(1 if findings else 0)


def main():
    """Main CLI entry point."""
    try:
        cli()
    except Exception as e:
        click.echo(f"❌ Error: {e}", err=True)
        sys.exit(1)

if __name__ == '__main__':
    main()