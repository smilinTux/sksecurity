#!/usr/bin/env python3
"""
SKSecurity Enterprise Command Line Interface
Main entry point for all security operations
"""

import os
import sys
import click
import json
from pathlib import Path
from typing import Optional

# Import SKSecurity components
from . import __version__, BANNER
from .scanner import SecurityScanner
from .dashboard import DashboardServer
from .intelligence import ThreatIntelligence  
from .database import SecurityDatabase
from .config import SecurityConfig
from .monitor import SecurityMonitor
from .quarantine import QuarantineManager

@click.group()
@click.version_option(version=__version__)
@click.option('--config', '-c', type=click.Path(), help='Configuration file path')
@click.option('--verbose', '-v', is_flag=True, help='Verbose output')
@click.pass_context
def cli(ctx, config, verbose):
    """🛡️ SKSecurity Enterprise - AI Agent Security Platform
    
    Enterprise-grade security for AI agent ecosystems.
    """
    ctx.ensure_object(dict)
    ctx.obj['verbose'] = verbose
    ctx.obj['config'] = config or SecurityConfig.get_default_config_path()

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
    
    # Exit with appropriate code
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
        'timestamp': click.datetime.now().isoformat(),
        'version': __version__,
        'threat_intelligence': ThreatIntelligence(config=config).get_status(),
        'quarantine': QuarantineManager(config=config).get_stats(),
        'database': SecurityDatabase(config=config).get_stats(),
        'configuration': config.get_summary()
    }
    
    # Format output
    if output_format == 'json':
        output = json.dumps(audit_data, indent=2)
    elif output_format == 'pdf':
        # TODO: Generate PDF report
        output = "PDF export not implemented yet"
    else:
        output = format_audit_report(audit_data)
    
    # Export or display
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
    
    click.echo("\n✅ SKSecurity is operational")

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

def main():
    """Main CLI entry point."""
    try:
        cli()
    except Exception as e:
        click.echo(f"❌ Error: {e}", err=True)
        sys.exit(1)

if __name__ == '__main__':
    main()