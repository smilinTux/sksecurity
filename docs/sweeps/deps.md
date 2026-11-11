# deps sweep

`sksecurity sweep deps` audits every fleet Python environment for packages with known
vulnerabilities. It is report-only: it never installs, upgrades or modifies anything.

## How it works

- Tool: `pip-audit` (isolated venv `~/.venvs/pip-audit`, symlinked into `~/.local/bin`).
  Resolved from `SKSECURITY_PIP_AUDIT`, then `PATH`, then `~/.local/bin`. If it is missing
  the sweep emits one low `tool.missing` finding.
- Targets: `~/.skenv`, every `~/.venvs/*` except `pip-audit`, and `SKSECURITY_VENV` if set
  (the same locations the runtime installer looks at). Each is audited with
  `pip-audit --path <site-packages> --format json`.
- Committed `~/clawd/skcapstone-repos/*/requirements*.txt` files are also audited, but only
  when every line is pinned (`name==version`), using `-r --no-deps --disable-pip`, so nothing
  is resolved, built or installed. Unpinned files are skipped.
- Editable and local packages (the SK* packages) are not on PyPI. pip-audit reports them as
  skipped and the sweep ignores them.

## Findings

One finding per (environment, package). All of the package's vulnerability ids
are listed in the summary and kept per-vuln (id, aliases, fix versions, CVSS,
severity) in `details.vulns`; the worst severity wins. This keeps ITIL to one
incident per package instead of one per CVE.

| Field | Value |
| --- | --- |
| klass | `dep.vuln` |
| location | `<env>: <pkg>==<version>` |
| summary | package, count, and every vulnerability id with its aliases (CVE, GHSA) |
| remediation | `upgrade to <fix versions>` or `no fix released` |
| fingerprint | environment + package (not the version, not the vulnerability set) |

Severity: `high` when a fix version exists, `medium` when none. `critical` when OSV
(`https://api.osv.dev/v1/vulns/<id>`) reports a CVSS base score of 9.0 or more. OSV answers are
cached in `~/.cache/sksecurity/osv-severity.json` for 7 days. If OSV is unreachable the sweep
stops asking for the rest of the run and uses the high/medium rule; it does not fail.

A failure or timeout on one environment yields one low `tool.error` finding and the sweep
continues.

## Options

`--opt venv=PATH` audits only that environment. `--opt requirements=PATH` audits only that
requirements file. `--opt timeout=SECONDS` (default 300 per target). `--opt osv=off` skips OSV.

Config file `~/.config/sksecurity/sweep-deps.yaml` (all keys optional):

```yaml
venvs: [~/.skenv, ~/.venvs/skops]
requirements: []        # explicit list; omit to glob the skcapstone repos
exclude: [~/.venvs/old]
timeout: 300
osv: on
```
