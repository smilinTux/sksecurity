"""Filesystem secret and permission sweep (``sksecurity sweep fs``).

Report-only: nothing here moves, deletes, chmods or edits a scanned file, and
no finding carries a secret value (location, class, rule and a salted digest
only). See docs/sweeps/fs.md.

Two engines:

* gitleaks ``dir`` mode with ``--redact`` (optional; one ``tool.missing``
  finding when absent), whose JSON report is parsed into a temp file and the
  ``Secret``/``Match`` fields are dropped immediately.
* Native rules sized to the KEDB ``ke-leak-*`` classes plus permission rules.
"""

from __future__ import annotations

import fnmatch
import json
import os
import re
import shlex
import shutil
import stat
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Dict, Iterator, List, Optional, Set, Tuple

from ..findings import Finding, make_fingerprint, value_digest

NAME = "fs"
HELP = "Secrets and permissions on the local filesystem (gitleaks + native rules)"

CONFIG_PATH = "~/.config/sksecurity/sweep-fs.yaml"

DEFAULT_ROOTS = [
    "~/clawd",
    "~/.config",
    "~/.skcapstone",
    "~/.hermes",
    "~/skworld-worktrees",
    "~/.skcapstone/agents/*/sessions",
    "~/.claude/projects",
]

#: Directory basenames never descended into.
PRUNE_DIRS = {
    "node_modules", ".venv", "venv", ".skenv", "__pycache__", ".cache", ".npm",
    ".mypy_cache", ".pytest_cache", ".ruff_cache", ".tox", ".gradle", "site-packages",
    ".cargo", ".rustup", ".git-objects",
}
#: Path globs (fnmatch on the full path) skipped entirely: sanctioned stores.
DEFAULT_EXCLUDE = [
    "*/skvault/*", "*/.skvault/*", "*/skvault",
    "*/gogcli/keyring*", "*/gog/keyring*",
    "*/.git/objects/*", "*/.git/objects",
]

SYSTEMD_DIRS = ["~/.config/systemd/user", "/etc/systemd/system"]
UNIT_SUFFIXES = (".service", ".conf", ".socket", ".timer", ".mount", ".path")

MAX_NATIVE_BYTES = 200 * 1024 * 1024
MAX_LINE = 16 * 1024 * 1024

_SECRET_KEY = re.compile(
    r"(TOKEN|PASSWORD|PASSWD|SECRET|API_?KEY|APIKEY|PRIVATE_?KEY|CREDENTIAL)", re.I)
_DSN_KEY = re.compile(r"(DSN|DATABASE_URL|_URL)$", re.I)
_DSN_RE = re.compile(
    r"\b(postgres(?:ql)?|mysql|mariadb|redis|rediss|mongodb(?:\+srv)?)://"
    r"([^\s:/@\"'<>]+):([^\s@/\"'<>]+)@")
_PLACEHOLDER = re.compile(
    r"^(\*+|x+|\.+|password|passwd|pass|secret|changeme|redacted|your[-_]?.*|"
    r"<.*>|\$\{?.*|%.*|\{.*\}|example|test|user|dummy|none|null)$", re.I)
_GIT_URL = re.compile(r"^\s*url\s*=\s*(https?)://([^/@\s]+)@", re.I | re.M)
_TOKEN_PREFIX = re.compile(
    r"^(ghp_|gho_|ghu_|ghs_|ghr_|github_pat_|glpat-|npm_|sk-|AKIA|ASIA|xox[abp]-)")
_SECRET_NAME = re.compile(r"(secret|token|credential)", re.I)
_SECRET_NAME_EXT = {"", ".env", ".conf", ".json", ".yaml", ".yml", ".toml", ".ini",
                    ".key", ".pem", ".txt", ".cfg", ".token"}
_NOT_SECRET_NAME = re.compile(r"(tokeniz|example|sample|template|\.dist$|\.pub$)", re.I)

#: gitleaks rule id fragments that mean a live provider credential.
_CRITICAL_RULES = ("private-key", "aws", "github", "gitlab", "gcp", "azure", "openai",
                   "anthropic", "stripe", "slack", "npm", "pypi", "digitalocean",
                   "nvidia", "huggingface", "cloudflare", "telegram")

REMEDIATION = {
    "secret.git-remote-credential": (
        "Rotate the token, then set the remote without credentials and use a "
        "credential helper or the gh keyring."),
    "secret.systemd-env": (
        "Rotate the secret and move it to an EnvironmentFile with mode 0600 "
        "outside any repo (or LoadCredential=)."),
    "secret.tracked-env": (
        "Rotate every value in it, git rm --cached the file, add it to "
        ".gitignore, and purge history if the repo is shared."),
    "secret.dsn-in-transcript": (
        "Rotate that database password; avoid pasting DSNs with passwords into "
        "sessions or shell commands (use PGPASSFILE or an env var)."),
    "secret.gitleaks": "Rotate the credential and move it to a sanctioned secret store.",
    "perm.secret-file": "chmod 600 the file (owner-only) and check its owner.",
    "perm.secret-dir": "chmod go-w the directory.",
    "tool.missing": "Install the pinned gitleaks binary or set SKSECURITY_GITLEAKS.",
    "sweep.truncated": "Raise the time_budget option or narrow the roots.",
}


# ---------------------------------------------------------------- config ----

def _load_config(path: Optional[str]) -> dict:
    p = Path(path or CONFIG_PATH).expanduser()
    if not p.is_file():
        return {}
    try:
        import yaml
        data = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _expand_roots(patterns: List[str]) -> List[Path]:
    out: List[Path] = []
    for pat in patterns:
        pat = os.path.expanduser(str(pat))
        if any(c in pat for c in "*?["):
            import glob
            out.extend(Path(m) for m in sorted(glob.glob(pat)) if os.path.isdir(m))
        elif os.path.isdir(pat):
            out.append(Path(pat))
    seen: Set[str] = set()
    uniq: List[Path] = []
    for p in out:
        rp = os.path.realpath(p)
        if rp not in seen:
            seen.add(rp)
            uniq.append(p)
    # Drop roots nested inside another root (already walked).
    keep = [p for p in uniq
            if not any(q is not p and os.path.realpath(p).startswith(os.path.realpath(q) + os.sep)
                       for q in uniq)]
    return keep


def _glob_to_re(glob: str) -> str:
    """Glob (fnmatch style, ``*`` crosses ``/``) to an RE2-safe regex."""
    out = []
    for ch in glob:
        if ch == "*":
            out.append(".*")
        elif ch == "?":
            out.append(".")
        else:
            out.append(re.escape(ch))
    return "^" + "".join(out) + "$"


# ----------------------------------------------------------------- walker ---

class _Budget:
    def __init__(self, seconds: float) -> None:
        self.deadline = time.monotonic() + seconds if seconds > 0 else None
        self.hit = False

    def left(self) -> Optional[float]:
        return None if self.deadline is None else self.deadline - time.monotonic()

    def over(self) -> bool:
        if self.deadline is not None and time.monotonic() > self.deadline:
            self.hit = True
        return self.hit


_RE_CACHE: Dict[Tuple[str, ...], "re.Pattern"] = {}


def _excluded(path: str, globs: List[str]) -> bool:
    """fnmatch against any glob, via one cached combined regex (hot path)."""
    key = tuple(globs)
    rx = _RE_CACHE.get(key)
    if rx is None:
        rx = re.compile("|".join(f"(?:{fnmatch.translate(g)})" for g in globs) or "(?!)")
        _RE_CACHE[key] = rx
    return rx.match(path) is not None


def _allowed(path: str, allow: List[str]) -> bool:
    return bool(allow) and _excluded(path, allow)


def _walk(roots: List[Path], exclude: List[str], budget: _Budget
          ) -> Iterator[Tuple[str, List[str], List[str]]]:
    """os.walk without following symlinks; prunes caches, venvs, excluded stores.

    ``.git`` dirs are yielded as part of their parent's dirnames but never
    descended into (the git rules read the few files they need directly).
    """
    seen: Set[str] = set()
    for root in roots:
        for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
            if budget.over():
                return
            real = os.path.realpath(dirpath)
            if real in seen:
                dirnames[:] = []
                continue
            seen.add(real)
            dirnames[:] = [
                d for d in dirnames
                if d not in PRUNE_DIRS and not _excluded(os.path.join(dirpath, d), exclude)]
            yield dirpath, list(dirnames), filenames
            if ".git" in dirnames:
                dirnames.remove(".git")


# ------------------------------------------------------------ name classes --

def _is_env_name(name: str) -> bool:
    if _NOT_SECRET_NAME.search(name):
        return False
    return name == ".env" or name.endswith(".env") or name.startswith(".env.")


def _secret_kind(path: str, name: str) -> Optional[str]:
    """Why this file is considered secret-bearing, or None."""
    low = path.replace(os.sep, "/")
    if _NOT_SECRET_NAME.search(name):
        return None
    if _is_env_name(name):
        return "env-file"
    if "/environment.d/" in low and name.endswith(".conf"):
        return "environment.d"
    if "/.ssh/" in low and not name.endswith(".pub") and name not in (
            "known_hosts", "known_hosts.old", "config", "authorized_keys", "authorized_keys2"):
        return "ssh-key"
    if "keyring" in low.rsplit("/", 1)[0].lower() or name.endswith(".keyring"):
        return "keyring"
    if "/secrets/" in low or "/.secrets/" in low:
        return "secrets-dir"
    ext = os.path.splitext(name)[1].lower()
    if _SECRET_NAME.search(name) and ext in _SECRET_NAME_EXT:
        return "secret-name"
    return None


def _perm_problem(st: os.stat_result) -> Optional[str]:
    mode = stat.S_IMODE(st.st_mode)
    if mode & 0o044:
        return f"mode {mode:04o} readable by group/other"
    if st.st_uid != os.getuid():
        return "owned by another user"
    return None


# ------------------------------------------------------------ small helpers -

def _read_lines(path: str) -> Iterator[Tuple[int, str]]:
    try:
        if os.path.getsize(path) > MAX_NATIVE_BYTES:
            return
        with open(path, "rb") as fh:
            for n, raw in enumerate(fh, 1):
                yield n, raw[:MAX_LINE].decode("utf-8", errors="replace")
    except OSError:
        return


def _guard():
    from ..secret_guard import SecretGuard
    return SecretGuard()


def _guard_severity(text: str) -> Optional[str]:
    """'critical' if SecretGuard sees a critical-class secret in text, else None."""
    try:
        for sf in _guard().scan_text(text, source="<line>"):
            if sf.severity.upper() == "CRITICAL":
                return "critical"
            return "high"
    except Exception:
        return None
    return None


def _real_password(pw: str) -> bool:
    return len(pw) >= 4 and not _PLACEHOLDER.match(pw)


# ------------------------------------------------------------ native rules --

def _rule_git_config(cfg: str) -> List[Finding]:
    out: List[Finding] = []
    try:
        text = Path(cfg).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return out
    for m in _GIT_URL.finditer(text):
        userinfo = m.group(2)
        if ":" in userinfo:
            user, secret = userinfo.split(":", 1)
        else:
            user, secret = "", userinfo
        if not secret or _PLACEHOLDER.match(secret):
            continue
        # Bare "user@" with no password is not a credential.
        if not user and not _TOKEN_PREFIX.match(secret) and len(secret) < 16:
            continue
        line = text.count("\n", 0, m.start()) + 1
        digest = value_digest(secret)
        sev = "critical" if _TOKEN_PREFIX.match(secret) else "high"
        out.append(Finding(
            sweep=NAME, klass="secret.git-remote-credential", severity=sev,
            location=f"{cfg}:{line}",
            summary="credential embedded in a git remote URL",
            fingerprint=make_fingerprint(NAME, "secret.git-remote-credential", cfg, digest),
            rule="git-remote-userinfo", kedb="ke-leak-github-pat-dvre",
            remediation=REMEDIATION["secret.git-remote-credential"],
            details={"digest": digest, "scheme": m.group(1).lower()}))
    return out


def _rule_systemd_unit(path: str) -> List[Finding]:
    out: List[Finding] = []
    seen: Set[str] = set()
    env_files: List[str] = []
    for n, line in _read_lines(path):
        s = line.strip()
        if s.startswith("EnvironmentFile="):
            env_files.append(s.split("=", 1)[1].lstrip("-").strip())
            continue
        if not s.startswith("Environment="):
            continue
        try:
            assigns = shlex.split(s.split("=", 1)[1])
        except ValueError:
            assigns = s.split("=", 1)[1].split()
        for a in assigns:
            if "=" not in a:
                continue
            key, val = a.split("=", 1)
            if not val or val.startswith(("%", "$")):
                continue
            dsn = _DSN_RE.search(val)
            looks_key = bool(_SECRET_KEY.search(key))
            guard = _guard_severity(val)
            dsn_pw = bool(dsn and _real_password(dsn.group(3)))
            if not (guard or dsn_pw or (looks_key and _real_password(val))):
                continue
            digest = value_digest(dsn.group(3) if dsn_pw else val)
            if digest in seen:
                continue
            seen.add(digest)
            sev = guard or "high"
            out.append(Finding(
                sweep=NAME, klass="secret.systemd-env", severity=sev,
                location=f"{path}:{n}",
                summary=f"secret-looking value in Environment= ({key})",
                fingerprint=make_fingerprint(NAME, "secret.systemd-env", path, key, digest),
                rule="systemd-environment", kedb="ke-leak-nvidia-apikey",
                remediation=REMEDIATION["secret.systemd-env"],
                details={"digest": digest, "key": key}))
    # EnvironmentFile content is a sanctioned secret home at 0600. Only look
    # inside one that group/other can read (it is then also a perm finding).
    for ef in env_files:
        if not os.path.isabs(ef) or any(c in ef for c in "%$*"):
            continue
        try:
            st = os.stat(ef)
        except OSError:
            continue
        if not (stat.S_IMODE(st.st_mode) & 0o044):
            continue
        for n, line in _read_lines(ef):
            if "=" not in line or line.lstrip().startswith("#"):
                continue
            key, val = line.strip().split("=", 1)
            val = val.strip().strip("\"'")
            if _SECRET_KEY.search(key) and _real_password(val):
                digest = value_digest(val)
                out.append(Finding(
                    sweep=NAME, klass="secret.systemd-env", severity="high",
                    location=f"{ef}:{n}",
                    summary=f"secret in a world/group-readable EnvironmentFile ({key})",
                    fingerprint=make_fingerprint(NAME, "secret.systemd-env", ef, key, digest),
                    rule="systemd-environmentfile", kedb="ke-leak-nvidia-apikey",
                    remediation=REMEDIATION["secret.systemd-env"],
                    details={"digest": digest, "key": key, "referenced_by": path}))
    return out


def _git_common_dir(repo: str) -> Optional[str]:
    gitp = os.path.join(repo, ".git")
    if os.path.isdir(gitp):
        return os.path.realpath(gitp)
    try:
        txt = Path(gitp).read_text(encoding="utf-8", errors="replace").strip()
    except OSError:
        return None
    if not txt.startswith("gitdir:"):
        return None
    gd = os.path.realpath(os.path.join(repo, txt.split(":", 1)[1].strip()))
    parent = os.path.dirname(gd)
    if os.path.basename(parent) == "worktrees":
        return os.path.dirname(parent)
    return gd


def _rule_tracked_env(repo: str, timeout: float) -> List[Finding]:
    out: List[Finding] = []
    try:
        proc = subprocess.run(
            ["git", "-c", "safe.directory=*", "-C", repo, "ls-files", "-z"],
            capture_output=True, timeout=max(5.0, min(timeout, 60.0)), check=False)
    except (OSError, subprocess.TimeoutExpired):
        return out
    if proc.returncode != 0:
        return out
    for rel in proc.stdout.decode("utf-8", errors="replace").split("\0"):
        if not rel or not _is_env_name(os.path.basename(rel)):
            continue
        full = os.path.join(repo, rel)
        try:
            if os.path.getsize(full) == 0:
                continue
        except OSError:
            continue
        out.append(Finding(
            sweep=NAME, klass="secret.tracked-env", severity="high", location=full,
            summary="env file is tracked in git",
            fingerprint=make_fingerprint(NAME, "secret.tracked-env", full),
            rule="git-ls-files-env", kedb="ke-leak-skgentis-wallet-keys",
            remediation=REMEDIATION["secret.tracked-env"],
            details={"repo": repo, "relpath": rel}))
    return out


def _rule_dsn_in_file(path: str) -> List[Finding]:
    out: List[Finding] = []
    seen: Set[str] = set()
    for n, line in _read_lines(path):
        if "://" not in line:
            continue
        for m in _DSN_RE.finditer(line):
            pw = m.group(3)
            if not _real_password(pw):
                continue
            digest = value_digest(pw)
            if digest in seen:
                continue
            seen.add(digest)
            out.append(Finding(
                sweep=NAME, klass="secret.dsn-in-transcript", severity="high",
                location=f"{path}:{n}",
                summary=f"{m.group(1)} DSN with a password in a transcript or history",
                fingerprint=make_fingerprint(NAME, "secret.dsn-in-transcript", path, digest),
                rule="dsn-with-password", kedb=None,
                remediation=REMEDIATION["secret.dsn-in-transcript"],
                details={"digest": digest, "scheme": m.group(1)}))
    return out


def _rule_perms(path: str, name: str, dirs_done: Set[str]) -> Tuple[List[Finding], bool]:
    """Returns (findings, file_is_sanctioned). Sanctioned = secret-bearing and
    owner-only, so its content is the intended secret and is not scanned."""
    kind = _secret_kind(path, name)
    if not kind:
        return [], False
    try:
        st = os.lstat(path)
    except OSError:
        return [], False
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode):
        return [], False
    out: List[Finding] = []
    problem = _perm_problem(st)
    if problem:
        out.append(Finding(
            sweep=NAME, klass="perm.secret-file", severity="medium", location=path,
            summary=f"secret-bearing file ({kind}): {problem}",
            fingerprint=make_fingerprint(NAME, "perm.secret-file", path),
            rule=f"perm-{kind}", remediation=REMEDIATION["perm.secret-file"],
            details={"kind": kind, "mode": f"{stat.S_IMODE(st.st_mode):04o}"}))
    parent = os.path.dirname(path)
    if parent not in dirs_done:
        dirs_done.add(parent)
        try:
            pst = os.stat(parent)
            pmode = stat.S_IMODE(pst.st_mode)
            sticky = bool(pst.st_mode & stat.S_ISVTX)
            if pmode & 0o022 and not sticky:
                out.append(Finding(
                    sweep=NAME, klass="perm.secret-dir", severity="medium", location=parent,
                    summary=f"directory holding secret-bearing files is writable by group/other (mode {pmode:04o})",
                    fingerprint=make_fingerprint(NAME, "perm.secret-dir", parent),
                    rule="perm-dir-writable", remediation=REMEDIATION["perm.secret-dir"],
                    details={"mode": f"{pmode:04o}"}))
        except OSError:
            pass
    return out, problem is None


# --------------------------------------------------------------- gitleaks ---

def _find_gitleaks() -> Optional[str]:
    env = os.environ.get("SKSECURITY_GITLEAKS")
    if env:
        return env if os.access(env, os.X_OK) else None
    return shutil.which("gitleaks")


def _gitleaks_severity(rule: str) -> str:
    r = rule.lower()
    return "critical" if any(h in r for h in _CRITICAL_RULES) else "high"


def _run_gitleaks(binary: str, root: Path, exclude: List[str], timeout: Optional[float]
                  ) -> Tuple[List[dict], Optional[str]]:
    """Run gitleaks on one root. Returns (records without values, error)."""
    allow = [r"(^|/)(%s)/" % "|".join(re.escape(d) for d in sorted(PRUNE_DIRS)),
             r"(^|/)\.git/"]
    allow += [_glob_to_re(g) for g in exclude]
    with tempfile.TemporaryDirectory(prefix="sksec-gl-") as td:
        os.chmod(td, 0o700)
        cfg = os.path.join(td, "gitleaks.toml")
        report_path = os.path.join(td, "report.json")
        lines = ["[extend]", "useDefault = true", "", "[allowlist]", "paths = ["]
        lines += ["  '''%s'''," % a for a in allow]
        lines += ["]"]
        Path(cfg).write_text("\n".join(lines), encoding="utf-8")
        cmd = [binary, "dir", str(root), "--redact", "--no-banner", "--no-color",
               "--exit-code", "0", "--max-target-megabytes", "5",
               "--report-format", "json", "--report-path", report_path, "-c", cfg]
        try:
            proc = subprocess.run(cmd, capture_output=True, timeout=timeout, check=False)
        except subprocess.TimeoutExpired:
            return [], "timeout"
        except OSError as e:
            return [], str(e)
        if proc.returncode != 0:
            return [], f"gitleaks exit {proc.returncode}"
        try:
            raw = json.loads(Path(report_path).read_text(encoding="utf-8") or "[]")
        except (OSError, ValueError):
            return [], "unreadable report"
        records = []
        for r in raw or []:
            # Drop Secret/Match immediately: keep location and rule only.
            records.append({"rule": r.get("RuleID", ""), "file": r.get("File", ""),
                            "line": r.get("StartLine", 0), "desc": r.get("Description", "")})
        raw = None
        return records, None


# ------------------------------------------------------------------- run ----

def run(**options) -> List[Finding]:
    cfg = _load_config(options.get("config"))
    roots_opt = options.get("root")
    custom_root = bool(roots_opt)
    patterns = [roots_opt] if roots_opt else list(cfg.get("roots") or DEFAULT_ROOTS)
    roots = _expand_roots(patterns)
    exclude = list(DEFAULT_EXCLUDE) + [os.path.expanduser(str(x)) for x in cfg.get("exclude") or []]
    allow = [os.path.expanduser(str(x)) for x in cfg.get("allow") or []]
    try:
        seconds = float(options.get("time_budget", cfg.get("time_budget", 900)))
    except (TypeError, ValueError):
        seconds = 900.0
    budget = _Budget(seconds)
    findings: List[Finding] = []

    sanctioned: Set[str] = set()
    dirs_done: Set[str] = set()
    repos_done: Set[str] = set()
    units_done: Set[str] = set()
    dsn_files: Set[str] = set()

    def add(items: List[Finding]) -> None:
        for f in items:
            if not _allowed(f.location.rsplit(":", 1)[0] if ":" in f.location else f.location, allow):
                findings.append(f)

    # gitleaks runs one process per root, concurrently with the native walk.
    gl = _find_gitleaks()
    pool = None
    gl_jobs = None
    if gl is not None:
        from concurrent.futures import ThreadPoolExecutor
        pool = ThreadPoolExecutor(max_workers=max(1, min(4, len(roots))))
        gl_jobs = [(r, pool.submit(_run_gitleaks, gl, r, exclude, budget.left())) for r in roots]

    for dirpath, dirnames, filenames in _walk(roots, exclude, budget):
        if ".git" in dirnames:
            common = _git_common_dir(dirpath)
            cfgp = os.path.join(dirpath, ".git", "config")
            if common and common not in repos_done:
                repos_done.add(common)
                if os.path.isfile(cfgp):
                    add(_rule_git_config(cfgp))
                wt = os.path.join(common, "worktrees")
                if os.path.isdir(wt):
                    for w in sorted(os.listdir(wt)):
                        wc = os.path.join(wt, w, "config.worktree")
                        if os.path.isfile(wc):
                            add(_rule_git_config(wc))
                add(_rule_tracked_env(dirpath, budget.left() or 60.0))
        elif ".git" in filenames:
            common = _git_common_dir(dirpath)
            if common and common not in repos_done:
                repos_done.add(common)
                cfgp = os.path.join(common, "config")
                if os.path.isfile(cfgp):
                    add(_rule_git_config(cfgp))
                add(_rule_tracked_env(dirpath, budget.left() or 60.0))
        in_systemd = "systemd" in dirpath.split(os.sep)
        for name in filenames:
            path = os.path.join(dirpath, name)
            if _excluded(path, exclude):
                continue
            pf, ok = _rule_perms(path, name, dirs_done)
            add(pf)
            if ok:
                sanctioned.add(path)
            if in_systemd and name.endswith(UNIT_SUFFIXES) and path not in units_done:
                units_done.add(path)
                add(_rule_systemd_unit(path))
            if (name.endswith(".jsonl") or name in (".bash_history", ".zsh_history")) \
                    and path not in dsn_files:
                dsn_files.add(path)
                add(_rule_dsn_in_file(path))

    if not custom_root:
        for h in (".bash_history", ".zsh_history"):
            p = os.path.expanduser(f"~/{h}")
            if os.path.isfile(p) and p not in dsn_files:
                dsn_files.add(p)
                add(_rule_dsn_in_file(p))
        for d in SYSTEMD_DIRS:
            d = os.path.expanduser(d)
            if not os.path.isdir(d):
                continue
            for dp, _dn, fns in os.walk(d, followlinks=False):
                for fn in fns:
                    p = os.path.join(dp, fn)
                    if fn.endswith(UNIT_SUFFIXES) and p not in units_done:
                        units_done.add(p)
                        add(_rule_systemd_unit(p))

    # gitleaks results (started before the walk, see below)
    if gl_jobs is None:
        findings.append(Finding(
            sweep=NAME, klass="tool.missing", severity="low", location="gitleaks",
            summary="gitleaks not found; ran native rules only",
            fingerprint=make_fingerprint(NAME, "tool.missing", "gitleaks"),
            rule="gitleaks-missing", remediation=REMEDIATION["tool.missing"]))
    else:
        grouped: Dict[Tuple[str, str], List[int]] = {}
        for root, fut in gl_jobs:
            recs, err = fut.result()
            if err:
                if err == "timeout":
                    budget.hit = True
                findings.append(Finding(
                    sweep=NAME, klass="tool.error", severity="low", location=str(root),
                    summary=f"gitleaks did not complete ({err})",
                    fingerprint=make_fingerprint(NAME, "tool.error", str(root)),
                    rule="gitleaks-error"))
                continue
            for r in recs:
                f = r["file"]
                if f in sanctioned or _excluded(f, exclude):
                    continue
                grouped.setdefault((f, r["rule"]), []).append(int(r["line"] or 0))
        for (f, rule), lines in sorted(grouped.items()):
            if _allowed(f, allow):
                continue
            first = min(lines)
            findings.append(Finding(
                sweep=NAME, klass="secret.gitleaks", severity=_gitleaks_severity(rule),
                location=f"{f}:{first}" if first else f,
                summary=f"gitleaks rule {rule} matched ({len(lines)} occurrence(s))",
                fingerprint=make_fingerprint(NAME, "secret.gitleaks", f, rule),
                rule=rule, remediation=REMEDIATION["secret.gitleaks"],
                details={"occurrences": len(lines)}))
    if pool is not None:
        pool.shutdown(wait=True)

    if budget.hit:
        findings.append(Finding(
            sweep=NAME, klass="sweep.truncated", severity="low", location="time_budget",
            summary=f"time budget of {seconds:.0f}s reached; results are partial",
            fingerprint=make_fingerprint(NAME, "sweep.truncated"),
            rule="time-budget", remediation=REMEDIATION["sweep.truncated"]))
    return findings
