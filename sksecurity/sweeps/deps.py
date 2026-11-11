"""Dependency audit sweep: known-vulnerable packages in fleet Python environments.

Report-only. Runs ``pip-audit`` against the installed site-packages of each
environment (never installs, upgrades or builds anything). Packages that are
not on PyPI (editable installs, the SK* packages) are skipped cleanly.
"""

from __future__ import annotations

import glob
import json
import math
import os
import re
import shutil
import subprocess
import time
import urllib.request
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from ..findings import Finding, make_fingerprint

NAME = "deps"
HELP = "pip-audit every fleet Python environment (report-only)"

CONFIG_PATH = "~/.config/sksecurity/sweep-deps.yaml"
CACHE_PATH = "~/.cache/sksecurity/osv-severity.json"
OSV_URL = "https://api.osv.dev/v1/vulns/"
OSV_TTL = 7 * 24 * 3600
DEFAULT_TIMEOUT = 300
OSV_TIMEOUT = 3
REPO_GLOB = "~/clawd/skcapstone-repos/*/requirements*.txt"
EXCLUDE_NAMES = {"pip-audit"}

#: coverage of the last run() (targets audited, packages checked/skipped), for callers and tests.
LAST_STATS: Dict[str, Any] = {}
_SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def _finding(klass, severity, location, summary, *parts, **kw) -> Finding:
    return Finding(NAME, klass, severity, location, summary,
                   make_fingerprint(NAME, klass, *parts), rule=klass, **kw)


# ---- tool + targets -------------------------------------------------------

def find_tool() -> Optional[str]:
    env = os.environ.get("SKSECURITY_PIP_AUDIT")
    if env and os.access(env, os.X_OK):
        return env
    found = shutil.which("pip-audit")
    if found:
        return found
    local = os.path.expanduser("~/.local/bin/pip-audit")
    return local if os.access(local, os.X_OK) else None


def load_config() -> Dict[str, Any]:
    path = os.path.expanduser(CONFIG_PATH)
    if not os.path.isfile(path):
        return {}
    try:
        import yaml
        data = yaml.safe_load(Path(path).read_text()) or {}
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _site_packages(env: str) -> Optional[str]:
    for pat in ("lib/python*/site-packages", "lib64/python*/site-packages"):
        hits = sorted(glob.glob(os.path.join(env, pat)))
        if hits:
            return hits[-1]
    return None


def discover_envs(venvs: List[str], excludes: List[str]) -> List[str]:
    """Fleet environments: explicit list, else ~/.skenv + ~/.venvs/* (as in runtime discovery)."""
    if venvs:
        cands = [os.path.expanduser(v) for v in venvs]
    else:
        cands = [os.path.expanduser("~/.skenv")]
        cands += sorted(glob.glob(os.path.expanduser("~/.venvs/*")))
        extra = os.environ.get("SKSECURITY_VENV")
        if extra:
            cands.append(os.path.expanduser(extra))
    skip = {os.path.realpath(os.path.expanduser(e)) for e in excludes}
    out, seen = [], set()
    for c in cands:
        real = os.path.realpath(c)
        if (real in seen or real in skip or os.path.basename(c.rstrip("/")) in EXCLUDE_NAMES
                or not os.path.isdir(c)):
            continue
        seen.add(real)
        out.append(c)
    return out


_PINNED = re.compile(r"^[A-Za-z0-9_.\-\[\]]+\s*==\s*[A-Za-z0-9_.!+\-]+\s*(;.*)?(\s+#.*)?$")


def _pinned_only(path: str) -> bool:
    """True if every requirement is `name==version`: auditable without resolving or building."""
    try:
        lines = Path(path).read_text().splitlines()
    except OSError:
        return False
    n = 0
    for raw in lines:
        line = raw.split(" #")[0].strip()
        if not line or line.startswith("#"):
            continue
        if not _PINNED.match(line):
            return False
        n += 1
    return n > 0


# ---- OSV severity (best effort) -------------------------------------------

def _cvss3_score(vector: str) -> Optional[float]:
    try:
        m = dict(p.split(":") for p in vector.split("/")[1:])
        av = {"N": .85, "A": .62, "L": .55, "P": .2}[m["AV"]]
        ac = {"L": .77, "H": .44}[m["AC"]]
        changed = m["S"] == "C"
        pr = {"N": .85, "L": .68 if changed else .62, "H": .5 if changed else .27}[m["PR"]]
        ui = {"N": .85, "R": .62}[m["UI"]]
        cia = {"H": .56, "L": .22, "N": 0}
        iss = 1 - (1 - cia[m["C"]]) * (1 - cia[m["I"]]) * (1 - cia[m["A"]])
        imp = 7.52 * (iss - .029) - 3.25 * (iss - .02) ** 15 if changed else 6.42 * iss
        if imp <= 0:
            return 0.0
        base = 1.08 * (imp + 8.22 * av * ac * pr * ui) if changed else imp + 8.22 * av * ac * pr * ui
        return math.ceil(min(base, 10) * 10) / 10
    except Exception:
        return None


def _osv_fetch(vuln_id: str) -> Optional[float]:
    """CVSS base score for an id from OSV, or None if unknown. Raises OSError on network failure."""
    req = urllib.request.Request(OSV_URL + vuln_id, headers={"User-Agent": "sksecurity-sweep"})
    try:
        with urllib.request.urlopen(req, timeout=OSV_TIMEOUT) as r:  # nosec B310 (fixed https URL)
            data = json.load(r)
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return None
        raise OSError(str(e)) from e
    except Exception as e:
        raise OSError(str(e)) from e
    for sev in data.get("severity", []):
        if str(sev.get("type", "")).startswith("CVSS_V3"):
            score = _cvss3_score(str(sev.get("score", "")))
            if score is not None:
                return score
    label = str((data.get("database_specific") or {}).get("severity", "")).upper()
    return {"CRITICAL": 9.5, "HIGH": 7.5, "MODERATE": 5.0, "LOW": 2.0}.get(label)


class OsvScores:
    """Cached OSV lookups. After one network failure the rest of the run skips OSV."""

    def __init__(self, enabled: bool = True):
        self.enabled = enabled
        self.path = os.path.expanduser(CACHE_PATH)
        self.cache: Dict[str, Any] = {}
        self.dirty = False
        try:
            self.cache = json.loads(Path(self.path).read_text())
        except Exception:
            self.cache = {}

    def score(self, vuln_ids: List[str]) -> Optional[float]:
        best = None
        for vid in vuln_ids:
            ent = self.cache.get(vid)
            if ent and time.time() - ent.get("ts", 0) < OSV_TTL:
                s = ent.get("score")
            elif not self.enabled:
                continue
            else:
                try:
                    s = _osv_fetch(vid)
                except OSError:
                    self.enabled = False  # OSV unreachable: fall back, do not fail
                    continue
                self.cache[vid] = {"score": s, "ts": time.time()}
                self.dirty = True
            if s is not None and (best is None or s > best):
                best = s
        return best

    def save(self) -> None:
        if not self.dirty:
            return
        try:
            os.makedirs(os.path.dirname(self.path), exist_ok=True)
            tmp = self.path + ".tmp"
            Path(tmp).write_text(json.dumps(self.cache))
            os.replace(tmp, self.path)
        except OSError:
            pass


# ---- audit ----------------------------------------------------------------

def _run_audit(tool: str, args: List[str], timeout: int) -> Dict[str, Any]:
    cmd = [tool, *args, "--format", "json", "--progress-spinner", "off"]
    p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)
    try:
        return json.loads(p.stdout)
    except ValueError:
        raise RuntimeError((p.stderr or p.stdout or f"exit {p.returncode}").strip()[-300:])


def _findings_for(label: str, data: Dict[str, Any], osv: OsvScores) -> Tuple[List[Finding], int, int]:
    out: List[Finding] = []
    checked = skipped = 0
    for dep in data.get("dependencies", []):
        if dep.get("skip_reason") is not None or "version" not in dep:
            skipped += 1  # editable / local / not on PyPI (the SK* packages)
            continue
        checked += 1
        pkg, ver = dep["name"], dep["version"]
        vulns: List[Dict[str, Any]] = []
        fixes_all: List[str] = []
        for v in dep.get("vulns", []):
            vid = v["id"]
            aliases = list(v.get("aliases") or [])
            fixes = list(v.get("fix_versions") or [])
            cvss = osv.score([vid, *aliases])
            sev = "critical" if cvss is not None and cvss >= 9 else ("high" if fixes else "medium")
            vulns.append({"vuln_id": vid, "aliases": aliases, "fix_versions": fixes,
                          "cvss": cvss, "severity": sev})
            fixes_all.extend(fixes)
        if not vulns:
            continue
        worst = min((v["severity"] for v in vulns), key=_SEV_RANK.__getitem__)
        ids = "; ".join(", ".join([v["vuln_id"], *v["aliases"]]) for v in vulns)
        unfixed = [v["vuln_id"] for v in vulns if not v["fix_versions"]]
        if fixes_all:
            rem = f"upgrade to {', '.join(sorted(set(fixes_all)))}"
            if unfixed:
                rem += f"; no fix released for {', '.join(unfixed)}"
        else:
            rem = "no fix released"
        n = len(vulns)
        # One finding per (environment, package): fingerprint excludes version and vuln ids.
        out.append(_finding(
            "dep.vuln", worst, f"{label}: {pkg}=={ver}",
            f"{pkg} {ver} has {n} known vulnerabilit{'y' if n == 1 else 'ies'}: {ids}",
            label, pkg.lower(), remediation=rem,
            details={"environment": label, "package": pkg, "version": ver,
                     "vuln_count": n, "vulns": vulns}))
    return out, checked, skipped


def run(**options) -> List[Finding]:
    tool = find_tool()
    if not tool:
        return [_finding("tool.missing", "low", "pip-audit",
                         "pip-audit not found (set SKSECURITY_PIP_AUDIT or install to ~/.local/bin)",
                         "pip-audit", remediation="install pip-audit in an isolated venv "
                         "(~/.venvs/pip-audit) and symlink it into ~/.local/bin")]
    cfg = load_config()
    timeout = int(options.get("timeout") or cfg.get("timeout") or DEFAULT_TIMEOUT)
    venvs = [options["venv"]] if options.get("venv") else list(cfg.get("venvs") or [])
    if options.get("requirements"):
        reqs = [os.path.expanduser(options["requirements"])]
    elif options.get("venv"):
        reqs = []
    elif "requirements" in cfg:
        reqs = [os.path.expanduser(r) for r in cfg.get("requirements") or []]
    else:
        reqs = sorted(glob.glob(os.path.expanduser(REPO_GLOB)))
    envs = discover_envs(venvs, list(cfg.get("exclude") or []))
    osv = OsvScores(enabled=str(options.get("osv", cfg.get("osv", "on"))).lower() not in ("off", "0", "false", "no"))

    findings: List[Finding] = []
    stats = LAST_STATS
    stats.clear()
    stats.update(targets=[], packages_checked=0, packages_skipped=0)
    targets: List[Tuple[str, List[str]]] = []
    for env in envs:
        sp = _site_packages(env)
        if sp:
            targets.append((env, ["--path", sp]))
    for r in reqs:
        if _pinned_only(r):  # never resolve or build: pinned, no deps, no pip
            targets.append((r, ["-r", r, "--no-deps", "--disable-pip"]))

    for label, args in targets:
        try:
            data = _run_audit(tool, args, timeout)
        except subprocess.TimeoutExpired:
            findings.append(_finding("tool.error", "low", label,
                                     f"pip-audit timed out after {timeout}s", label, "timeout"))
            continue
        except Exception as e:
            findings.append(_finding("tool.error", "low", label,
                                     f"pip-audit failed: {str(e)[:200]}", label, "error"))
            continue
        fs, checked, skipped = _findings_for(label, data, osv)
        stats["targets"].append(label)
        stats["packages_checked"] += checked
        stats["packages_skipped"] += skipped
        findings.extend(fs)
    osv.save()
    return findings
