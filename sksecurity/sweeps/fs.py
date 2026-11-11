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

#: Coverage notes of the last run() for callers and tests.
LAST_STATS: Dict[str, object] = {}

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
    # Browser profiles: embedded public API keys and cached tokens, not our secrets
    # (they were ~1000 gitleaks hits, mostly gcp-api-key and generic-api-key).
    "*/.config/google-chrome", "*/.config/google-chrome/*",
    "*/.config/chrome-cdp", "*/.config/chrome-cdp/*",
    "*/.config/chromium", "*/.config/chromium/*",
    "*/.config/BraveSoftware", "*/.config/BraveSoftware/*",
    "*/.config/microsoft-edge", "*/.config/microsoft-edge/*",
    "*/.mozilla", "*/.mozilla/*",
    "*/.hermes/cache", "*/.hermes/cache/*",
    "*/.config/vivaldi*", "*/.config/opera*",
    # Electron / Chromium app stores (VS Code, VSCodium, Docker Desktop, T3, ...):
    # HTTP caches and profile databases hold cached web responses and the app's
    # own session tokens, not leaked secrets. Found on .41 on 2026-11-11, where
    # they were most of ~2700 gitleaks hits.
    "*/Cache/Cache_Data/*", "*/Code Cache/*", "*/GPUCache/*", "*/CachedData/*",
    "*/Service Worker/CacheStorage/*", "*/Service Worker/ScriptCache/*",
    "*/shared_proto_db/*", "*/IndexedDB/*", "*/Local Storage/leveldb/*",
    "*/Session Storage/*",
    # The scanner's own fixtures are fake secrets by design.
    "*/sksecurity/tests/*",
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
_KEY_EXT = {".pem", ".key"}
_DOC_NAME = re.compile(r"(\.(md|rst|txt|example|sample|tpl|template|j2|gitkeep|dist)$|^readme)", re.I)
_NOT_SECRET_NAME = re.compile(r"(tokeniz|example|sample|template|\.dist$|\.pub$)", re.I)

#: gitleaks rule id fragments that mean a live provider credential.
_CRITICAL_RULES = ("private-key", "aws", "github", "gitlab", "gcp", "azure", "openai",
                   "anthropic", "stripe", "slack", "npm", "pypi", "digitalocean",
                   "nvidia", "huggingface", "cloudflare", "telegram")

#: Low-precision (entropy or shape based) gitleaks rules. They matched thousands of
#: distinct non-secret strings (ids, hashes, cached tokens), so they rate medium
#: (roll-up, never an incident each); provider-specific rules stay critical/high.
_GENERIC_RULES = ("generic-api-key", "curl-auth-header", "curl-auth-user", "jwt")

#: Default per-root (per gitleaks unit) time budget in seconds.
GITLEAKS_BUDGET = 300

#: Classes merged across files by value digest: one leaked value, many places.
_MERGE_BY_DIGEST = ("secret.dsn-in-transcript",)  # gitleaks hits are merged as parsed
MAX_LOCATIONS = 20

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
    """Why this file is considered secret-bearing, or None.

    Deliberately narrow (env files, environment.d, ssh private keys, keyrings,
    files under secrets/, *.pem and *.key). A name that merely contains
    "token" or "secret" is NOT enough: that matched source files and docs and
    produced thousands of findings.
    """
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
    if ("/secrets/" in low or "/.secrets/" in low) and not _DOC_NAME.search(name):
        return "secrets-dir"
    if os.path.splitext(name)[1].lower() in _KEY_EXT:
        return "key-file"
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


def _rule_perms(path: str, name: str, dirs_done: Set[str],
                in_repo: bool = False) -> Tuple[List[Finding], bool]:
    """Returns (findings, file_is_sanctioned). Sanctioned = secret-bearing and
    owner-only, so its content is the intended secret and is not scanned."""
    kind = _secret_kind(path, name)
    if not kind:
        return [], False
    if in_repo and kind == "secrets-dir":
        return [], False  # git checks out 0644: a mode on repo content is not actionable
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


def _gitleaks_severity(rule: str, path: str = "") -> str:
    """Provider rules are critical/high; the generic rules are medium everywhere."""
    r = rule.lower()
    if any(g in r for g in _GENERIC_RULES):
        return "medium"
    if r == "gcp-api-key":  # often a restricted/public browser key: high, not critical
        return "high"
    return "critical" if any(h in r for h in _CRITICAL_RULES) else "high"


def _match_digests(records: List[dict]) -> None:
    """Add ``digest`` to each record: salted hash of the matched slice of its line.

    gitleaks runs with --redact, so the value is not in its report. The slice
    is re-read from the file (StartColumn..EndColumn of StartLine), hashed and
    dropped at once; two copies of the same leaked line hash the same, which is
    what lets one value in many worktrees or transcripts be ONE finding. A
    record that cannot be read keeps ``digest=None`` and falls back to a
    (file, rule) identity.
    """
    by_file: Dict[str, List[dict]] = {}
    for r in records:
        r["digest"] = None
        by_file.setdefault(r["file"], []).append(r)
    for path, recs in by_file.items():
        try:
            if os.path.getsize(path) > MAX_NATIVE_BYTES:
                continue
            with open(path, "rb") as fh:
                lines = fh.read().splitlines()
        except OSError:
            continue
        for r in recs:
            n = int(r["line"] or 0)
            if not 1 <= n <= len(lines):
                continue
            raw = lines[n - 1]
            sc, ec = int(r.get("col0") or 0), int(r.get("col1") or 0)
            if r.get("endline", n) == n and 0 < sc <= ec:
                raw = raw[sc - 1:ec]
            r["digest"] = value_digest(raw.decode("utf-8", errors="replace"))
        lines = []  # drop file content


def _run_gitleaks(binary: str, root: Path, exclude: List[str], timeout: Optional[float],
                  skip_dirs: Optional[List[str]] = None) -> Tuple[List[dict], Optional[str]]:
    """Run gitleaks on one unit. Returns (records without values, error).

    ``skip_dirs`` are child directories handled by their own units (or skipped
    as duplicate worktrees): they are path-allowlisted here.
    """
    allow = [r"(^|/)(%s)/" % "|".join(re.escape(d) for d in sorted(PRUNE_DIRS)),
             r"(^|/)\.git/"]
    allow += [_glob_to_re(g) for g in exclude]
    allow += ["^%s/" % re.escape(d.rstrip("/")) for d in skip_dirs or []]
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
            # Drop Secret/Match immediately: keep location, rule and columns only.
            records.append({"rule": r.get("RuleID", ""), "file": r.get("File", ""),
                            "line": r.get("StartLine", 0), "endline": r.get("EndLine", 0),
                            "col0": r.get("StartColumn", 0), "col1": r.get("EndColumn", 0),
                            "desc": r.get("Description", "")})
        raw = None
        _match_digests(records)
        return records, None


def _repo_root_of(path: str) -> Optional[str]:
    """Main checkout of a linked worktree at ``path`` (real path), else None."""
    if not os.path.isfile(os.path.join(path, ".git")):
        return None
    common = _git_common_dir(path)
    if not common:
        return None
    return os.path.dirname(common) if os.path.basename(common) == ".git" else common


def _duplicate_worktree(path: str, roots: List[Path]) -> bool:
    """True if ``path`` is a linked worktree whose main checkout lies under a
    scanned root that does not contain ``path`` itself (e.g. ~/skworld-worktrees
    copies of repos that live under ~/clawd)."""
    main = _repo_root_of(path)
    if not main:
        return False
    me = os.path.realpath(path)
    for r in roots:
        rr = os.path.realpath(r)
        if (main == rr or main.startswith(rr + os.sep)) and not (me == rr or me.startswith(rr + os.sep)):
            return True
    return False


def _gitleaks_units(roots: List[Path], exclude: List[str], split: bool, skip_dup: bool,
                    default_budget: float, root_budgets: Dict[str, float]
                    ) -> Tuple[list, List[str]]:
    """(units, skipped_duplicate_worktrees). A unit is (path, skip_dirs, budget).

    A root with several child directories is split: one unit per child plus one
    for the root's own top-level files (children path-allowlisted). A slow tree
    then times out alone and the rest of the root still reports.
    """
    units: list = []
    skipped: List[str] = []
    for root in roots:
        budget = default_budget
        for pat, secs in root_budgets.items():
            if fnmatch.fnmatch(str(root), os.path.expanduser(pat)):
                budget = secs
        if skip_dup and _duplicate_worktree(str(root), roots):
            skipped.append(str(root))
            continue
        children: List[str] = []
        if split:
            try:
                for e in sorted(os.scandir(root), key=lambda x: x.name):
                    if (e.is_dir(follow_symlinks=False) and e.name not in PRUNE_DIRS
                            and e.name != ".git" and not _excluded(e.path, exclude)):
                        children.append(e.path)
            except OSError:
                children = []
        if len(children) < 2:
            units.append((root, [], budget))
            continue
        units.append((root, list(children), budget))
        for c in children:
            if skip_dup and _duplicate_worktree(c, roots):
                skipped.append(c)
                continue
            units.append((Path(c), [], budget))
    return units, skipped


def _merge_by_digest(findings: List[Finding]) -> List[Finding]:
    """One finding per (klass, rule, value digest) for the classes in
    ``_MERGE_BY_DIGEST``; the places it was seen go to ``details.locations``."""
    out: List[Finding] = []
    groups: Dict[Tuple[str, str, str], List[Finding]] = {}
    for f in findings:
        d = f.details.get("digest")
        if f.klass in _MERGE_BY_DIGEST and d:
            groups.setdefault((f.klass, f.rule, d), []).append(f)
        else:
            out.append(f)
    for (klass, rule, digest), items in groups.items():
        items.sort(key=lambda x: (_SEV_ORDER.get(x.severity, 9), x.location))
        head = items[0]
        locs = sorted({i.location for i in items})
        occ = sum(int(i.details.get("occurrences", 1)) for i in items)
        details = dict(head.details)
        details.update(locations=locs[:MAX_LOCATIONS], location_count=len(locs),
                       occurrences=occ)
        out.append(Finding(
            sweep=NAME, klass=klass, severity=head.severity, location=head.location,
            summary=(f"{head.summary} (same value in {len(locs)} location(s))"
                     if len(locs) > 1 else head.summary),
            fingerprint=make_fingerprint(NAME, klass, rule, digest), rule=rule,
            kedb=head.kedb, remediation=head.remediation, details=details))
    return out


_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def _collapse_perm_files(findings: List[Finding]) -> List[Finding]:
    """perm.secret-file: one finding per directory (one chmod fixes the dir's files).
    A perm.secret-dir finding for the same directory is folded into it."""
    out: List[Finding] = []
    by_dir: Dict[str, List[Finding]] = {}
    for f in findings:
        if f.klass == "perm.secret-file":
            by_dir.setdefault(os.path.dirname(f.location), []).append(f)
        else:
            out.append(f)
    folded = {f.location: f for f in out if f.klass == "perm.secret-dir" and f.location in by_dir}
    out = [f for f in out if f.location not in folded or f.klass != "perm.secret-dir"]
    for d, items in sorted(by_dir.items()):
        names = sorted(os.path.basename(i.location) for i in items)
        kinds = sorted({i.details.get("kind", "") for i in items})
        out.append(Finding(
            sweep=NAME, klass="perm.secret-file", severity="medium", location=d,
            summary=f"{len(items)} secret-bearing file(s) readable by group/other or "
                    f"foreign-owned ({', '.join(kinds)})",
            fingerprint=make_fingerprint(NAME, "perm.secret-file", d),
            rule="perm-secret-files", remediation=REMEDIATION["perm.secret-file"],
            details={"count": len(items), "files": names[:MAX_LOCATIONS], "kinds": kinds,
                     **({"dir_mode": folded[d].details.get("mode")} if d in folded else {})}))
    return out


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

    def _opt(name: str, default):
        return options.get(name, cfg.get(name, default))

    def _truthy(v) -> bool:
        return str(v).lower() not in ("off", "0", "false", "no")

    try:
        gl_budget = float(_opt("gitleaks_budget", GITLEAKS_BUDGET))
    except (TypeError, ValueError):
        gl_budget = float(GITLEAKS_BUDGET)
    root_budgets = {str(k): float(v) for k, v in (cfg.get("root_budgets") or {}).items()}
    gl_split = _truthy(_opt("gitleaks_split", True))
    gl_skip_dup = _truthy(_opt("gitleaks_skip_duplicate_worktrees", True))
    dup_dirs: Set[str] = set()
    repo_dirs: Set[str] = set()
    locs_by_key: Dict[Tuple[str, str], Set[str]] = {}

    sanctioned: Set[str] = set()
    dirs_done: Set[str] = set()
    repos_done: Set[str] = set()
    units_done: Set[str] = set()
    dsn_files: Set[str] = set()

    def add(items: List[Finding]) -> None:
        for f in items:
            if not _allowed(f.location.rsplit(":", 1)[0] if ":" in f.location else f.location, allow):
                findings.append(f)

    # gitleaks runs one process per unit (root, or child of a big root),
    # concurrently with the native walk, each with its own time budget.
    gl = _find_gitleaks()
    pool = None
    gl_jobs = None
    skipped_dups: List[str] = []
    if gl is not None:
        from concurrent.futures import ThreadPoolExecutor
        units, skipped_dups = _gitleaks_units(roots, exclude, gl_split, gl_skip_dup,
                                              gl_budget, root_budgets)
        dup_dirs.update(skipped_dups)
        pool = ThreadPoolExecutor(max_workers=max(1, min(4, len(units))))

        def _job(unit):
            path, skip_dirs, secs = unit
            left = budget.left()
            limit = secs if left is None else max(1.0, min(secs, left))
            return _run_gitleaks(gl, path, exclude, limit, skip_dirs)
        gl_jobs = [(u[0], pool.submit(_job, u)) for u in units]

    for dirpath, dirnames, filenames in _walk(roots, exclude, budget):
        if ".git" in dirnames or ".git" in filenames:
            repo_dirs.add(dirpath)
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
            if _duplicate_worktree(dirpath, roots):
                dup_dirs.add(dirpath)
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
            if dup_dirs and path.startswith(tuple(d + os.sep for d in dup_dirs)):
                pf, ok = [], False  # duplicate worktree: perms judged on the main checkout
            else:
                pf, ok = _rule_perms(path, name, dirs_done, in_repo=bool(
                    repo_dirs and path.startswith(tuple(d + os.sep for d in repo_dirs))))
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
        grouped: Dict[Tuple[str, str, str], List[int]] = {}
        for root, fut in gl_jobs:
            recs, err = fut.result()
            if err:
                if err == "timeout":
                    budget.hit = True
                findings.append(Finding(
                    sweep=NAME, klass="tool.error", severity="low", location=str(root),
                    summary=f"gitleaks did not complete on {root} ({err})",
                    fingerprint=make_fingerprint(NAME, "tool.error", str(root)),
                    rule="gitleaks-error",
                    remediation="Raise gitleaks_budget (or root_budgets for this path) "
                                "or exclude the tree."))
                continue
            for r in recs:
                f = r["file"]
                if f in sanctioned or _excluded(f, exclude) or _allowed(f, allow):
                    continue
                # Value digest when known (dedups copies); else file identity.
                ident = r.get("digest") or "file:" + f
                grouped.setdefault((r["rule"], ident, f if not r.get("digest") else ""),
                                   []).append(int(r["line"] or 0))
                if r.get("digest"):
                    locs_by_key.setdefault((r["rule"], ident), set()).add(
                        f"{f}:{int(r['line'] or 0)}" if r["line"] else f)
        for (rule, ident, nodigest_file), lines in sorted(grouped.items()):
            digest = None if ident.startswith("file:") else ident
            if digest:
                locs = sorted(locs_by_key[(rule, ident)])
                head = locs[0]
                path0 = head.rsplit(":", 1)[0] if ":" in head else head
                parts = (rule, digest)
                details = {"digest": digest, "occurrences": len(lines),
                           "locations": locs[:MAX_LOCATIONS], "location_count": len(locs)}
            else:
                path0 = nodigest_file
                first = min(lines)
                head = f"{path0}:{first}" if first else path0
                parts = (path0, rule)
                details = {"occurrences": len(lines)}
            findings.append(Finding(
                sweep=NAME, klass="secret.gitleaks", severity=_gitleaks_severity(rule, path0),
                location=head,
                summary=f"gitleaks rule {rule} matched ({len(lines)} occurrence(s))",
                fingerprint=make_fingerprint(NAME, "secret.gitleaks", *parts),
                rule=rule, remediation=REMEDIATION["secret.gitleaks"], details=details))
    if pool is not None:
        pool.shutdown(wait=True)

    findings = _collapse_perm_files(_merge_by_digest(findings))
    if skipped_dups:
        LAST_STATS["duplicate_worktrees_skipped"] = len(skipped_dups)
    if budget.hit:
        findings.append(Finding(
            sweep=NAME, klass="sweep.truncated", severity="low", location="time_budget",
            summary=f"time budget of {seconds:.0f}s reached; results are partial",
            fingerprint=make_fingerprint(NAME, "sweep.truncated"),
            rule="time-budget", remediation=REMEDIATION["sweep.truncated"]))
    return findings
