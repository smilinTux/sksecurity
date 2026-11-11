#!/usr/bin/env python3
"""
SKSecurity command line interface.

Commands: guard (secret leak prevention), claims (honest-claims gate),
screen (email/input screening) and the pqc-* post-quantum posture reports.
"""

import sys
import click
import json
from pathlib import Path

from . import __version__
from .email_screener import EmailScreener
from .secret_guard import SecretGuard, GuardResult
from .honest_claims import HonestClaimsScanner


@click.group()
@click.version_option(__version__, prog_name="sksecurity")
@click.option('--verbose', '-v', is_flag=True, help='Verbose output')
@click.pass_context
def cli(ctx, verbose):
    """SKSecurity: secret guard, honest-claims gate, input screening, PQC posture."""
    ctx.ensure_object(dict)
    ctx.obj['verbose'] = verbose


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
    """PQC POSTURE / coverage table - per surface: hybrid-pq / gated / classical.

    Scans the six security surfaces of the sovereign-comms ecosystem (DM ratchet,
    group, metadata, identity/signatures, at-rest, transport) and reports, for
    each, whether hybrid-PQ is the DEFAULT (hybrid-pq), merely AVAILABLE/opt-in/
    negotiated (gated), or ABSENT (classical). Grounded in the REAL wire-tags
    (pqdr1, kem_suite/x25519-mlkem768, aqid:+pqroute1, sig_suite, wrap_suite, the
    classical channel underlay) - never an out-of-band assumption.

    Live mode (default) up-rates group/at-rest from the operator's real objects
    only when the evidence is unambiguous; --static shows the honest default.
    Honest claims only - hybrid = either-leg (FIPS 203 / FIPS 204); never
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

    sys.exit(0 if result.is_safe else 1)


@cli.command(name="screen-file")
@click.argument('paths', nargs=-1, required=True, type=click.Path())
@click.option('--format', 'output_format', default='text', type=click.Choice(['text', 'json']))
def screen_file_cmd(paths, output_format):
    """Screen files (attachments) for malware, macros and disguised types.

    Report-only: files are never modified, moved or deleted. Exit 1 if any
    file is malicious.

    Example: sksecurity screen-file invoice.pdf --format json
    """
    from .filescreen import screen_files
    results = screen_files(paths)
    if output_format == 'json':
        click.echo(json.dumps({"files": [r.to_dict() for r in results]}, indent=2))
    else:
        for r in results:
            click.echo(f"{r.verdict.value.upper():10s} {r.path} (av: {r.av})")
            for f in r.findings:
                click.echo(f"  [{f.severity}] {f.description}")
    sys.exit(1 if any(r.is_malicious for r in results) else 0)


@cli.group()
def guard():
    """Secret leak prevention - detect and block credential leaks.

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


@cli.group()
def claims():
    """Honest-claims gate - block forbidden security overclaims.

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



@cli.command(name="sweep")
@click.argument("name")
@click.option("--format", "output_format", default="text", type=click.Choice(["text", "json"]))
@click.option("--report/--dry-run", "do_report", default=False,
              help="File findings into ITIL (default: dry run, print only).")
@click.option("--baseline", "do_baseline", is_flag=True,
              help="Accept the current findings as this host's backlog (writes "
                   "~/.local/state/sksecurity/baseline-NAME.json; with --report also files "
                   "ONE backlog incident). Later --report runs file only new findings.")
@click.option("--opt", "opts", multiple=True, help="Sweep option KEY=VALUE (repeatable).")
def sweep_cmd(name, output_format, do_report, do_baseline, opts):
    """Run a report-only sweep (fs, deps, mail). Never changes a scanned file."""
    from . import sweeps
    from .report import load_baseline, record_baseline, report
    options = dict(o.split("=", 1) for o in opts)
    findings = sweeps.get(name)(**options)
    if do_baseline:
        summary = record_baseline(findings, sweep=name, dry_run=not do_report)
    else:
        summary = report(findings, sweep=name, dry_run=not do_report)
    if output_format == "json":
        click.echo(json.dumps({"summary": summary,
                               "findings": [f.to_dict() for f in findings]}, indent=2))
    else:
        for f in findings:
            click.echo(f"[{f.severity}] {f.klass} {f.location}: {f.summary}")
        click.echo(json.dumps(summary))
    if do_report:
        # Scheduled mode: findings went to ITIL, so they are not a job failure.
        # Only a reporting failure is (exit 3), so sk-cron-run alerts on that.
        sys.exit(3 if summary.get("error") else 0)
    accepted = set() if do_baseline else load_baseline(name)
    sys.exit(0 if do_baseline else 1 if any(
        f.severity in ("critical", "high") and f.fingerprint not in accepted
        for f in findings) else 0)

def main():
    """Main CLI entry point."""
    try:
        cli()
    except Exception as e:
        click.echo(f"❌ Error: {e}", err=True)
        sys.exit(1)

if __name__ == '__main__':
    main()
