# sksecurity sweep fs

Report-only filesystem sweep for leaked secrets and loose permissions.
Nothing it scans is moved, deleted, chmod-ed or edited, and no finding carries
a secret value: location, class, rule and a salted digest (`value_digest`) only.

    sksecurity sweep fs --format json                 # dry run (default)
    sksecurity sweep fs --report                      # file into ITIL
    sksecurity sweep fs --opt root=/path/to/tree      # point at one tree
    sksecurity sweep fs --opt time_budget=300         # seconds, partial results flagged

## Roots and excludes

Defaults: `~/clawd`, `~/.config`, `~/.skcapstone`, `~/.hermes`,
`~/skworld-worktrees`, `~/.skcapstone/agents/*/sessions`, `~/.claude/projects`.
Override in `~/.config/sksecurity/sweep-fs.yaml` (needs PyYAML):

    roots: ["~/clawd", "~/.config"]
    exclude: ["*/some/store/*"]      # skipped entirely (fnmatch on full path)
    allow: ["*/fixtures/*"]          # findings under these paths are dropped
    time_budget: 900

Always skipped: `node_modules`, venvs, caches, `site-packages`, `.git/objects`,
skvault data and the gog keyring dir. A secret-bearing file (`*.env`,
`environment.d/*.conf`, ssh keys, keyring, `*secret*`/`*token*`/`*credential*`)
that is owner-only is the sanctioned home of a secret: its content is not
scanned, only its permissions.

## gitleaks

Binary from `SKSECURITY_GITLEAKS` or `PATH`. Runs `gitleaks dir --redact`
(no git history) with the JSON report in a 0700 temp dir; `Secret` and `Match`
are dropped on parse and the dir is removed. One finding per (file, rule),
klass `secret.gitleaks`. Missing binary: one low `tool.missing` finding and the
native rules still run.

## Native rules

| klass | what | severity | kedb |
|---|---|---|---|
| secret.git-remote-credential | user:pass@ or token@ in a remote URL in any `.git/config` or `config.worktree` | critical for a known token prefix, else high | ke-leak-github-pat-dvre |
| secret.systemd-env | secret-looking `Environment=` in user and system units (and readable EnvironmentFile content) | critical or high | ke-leak-nvidia-apikey |
| secret.tracked-env | `.env`, `*.env` in `git ls-files` | high | ke-leak-skgentis-wallet-keys |
| secret.dsn-in-transcript | postgres/mysql/redis/mongodb URL with a password in `*.jsonl` and shell history | high | none yet |
| perm.secret-file | secret-bearing file readable by group/other or owned by someone else | medium | |
| perm.secret-dir | parent dir of such a file writable by group/other | medium | |
| tool.missing, tool.error, sweep.truncated | the sweep itself | low | |

The fingerprint is stable across runs (path, rule, value digest); gitleaks
findings key on path and rule so a moved line does not reopen an incident.
