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
    gitleaks_budget: 300             # seconds per gitleaks unit (default 300)
    root_budgets: {"~/clawd": 600}   # per-root override (fnmatch on the root path)
    gitleaks_split: true             # one unit per child dir of a root (default on)
    gitleaks_skip_duplicate_worktrees: true

Always skipped: browser profiles (`~/.config/google-chrome`, `chrome-cdp`, `chromium`,
`BraveSoftware`, `microsoft-edge`, `~/.mozilla`), `node_modules`, venvs, caches, `site-packages`, `.git/objects`,
skvault data and the gog keyring dir. A secret-bearing file (`*.env`,
`environment.d/*.conf`, ssh keys, keyring, `*secret*`/`*token*`/`*credential*`)
that is owner-only is the sanctioned home of a secret: its content is not
scanned, only its permissions.

## gitleaks

Binary from `SKSECURITY_GITLEAKS` or `PATH`. Runs `gitleaks dir --redact`
(no git history) with the JSON report in a 0700 temp dir; `Secret` and `Match`
are dropped on parse and the dir is removed. Klass `secret.gitleaks`. Missing
binary: one low `tool.missing` finding and the native rules still run.

Noise control (see also docs/sweeps/reporting.md, Baseline):

- **Value dedup.** The report is redacted, so the sweep re-reads the matched slice of the line
  (StartLine, StartColumn..EndColumn), hashes it with the salted `value_digest` and drops it. One
  finding per (rule, value digest): the same leaked value in 30 worktrees or 100 transcripts is ONE
  finding, with `details.locations` (first 20), `location_count` and `occurrences`. A hit whose line
  cannot be re-read falls back to one finding per (file, rule). Fingerprint: rule + digest.
- **Units and budgets.** A root with several child directories runs as one gitleaks process per
  child plus one for its top-level files, each with its own budget (`gitleaks_budget`, default 300 s;
  `root_budgets` overrides per root), further capped by the overall `time_budget`. A unit that times
  out is one low `tool.error` finding naming it, the run is flagged `sweep.truncated`, and every
  other unit still reports.
- **Duplicate worktrees.** A linked git worktree whose main checkout lies under another scanned root
  (copies of `~/clawd` repos under `~/skworld-worktrees`) is skipped by gitleaks and by the
  permission rules. The native KEDB rules still run there (one git config per repo regardless).
  Disable with `gitleaks_skip_duplicate_worktrees: false`.
- **Generic rules.** `generic-api-key`, `curl-auth-header`, `curl-auth-user` and `jwt` are
  low-precision (thousands of distinct ids, hashes and cached tokens). They rate medium everywhere
  (one roll-up incident, never one each); provider rules (github, aws, private-key, ...) stay
  critical and are the per-finding incidents.

## Native rules

| klass | what | severity | kedb |
|---|---|---|---|
| secret.git-remote-credential | user:pass@ or token@ in a remote URL in any `.git/config` or `config.worktree` | critical for a known token prefix, else high | ke-leak-github-pat-dvre |
| secret.systemd-env | secret-looking `Environment=` in user and system units (and readable EnvironmentFile content) | critical or high | ke-leak-nvidia-apikey |
| secret.tracked-env | `.env`, `*.env` in `git ls-files` | high | ke-leak-skgentis-wallet-keys |
| secret.dsn-in-transcript | postgres/mysql/redis/mongodb URL with a password in `*.jsonl` and shell history; one finding per distinct password, locations in `details` | high | none yet |
| perm.secret-file | secret-bearing file readable by group/other or owned by someone else; ONE finding per directory (`details.files`; a writable-dir finding for the same directory is folded in as `dir_mode`); docs and templates under `secrets/` are ignored | medium | |
| perm.secret-dir | parent dir of such a file writable by group/other | medium | |
| tool.missing, tool.error, sweep.truncated | the sweep itself | low | |

Secret-bearing means: `.env`/`*.env`/`.env.*`, `environment.d/*.conf`, ssh private keys,
keyring files, anything under `secrets/`, `*.pem` and `*.key`. A name that merely contains
`token`, `secret` or `credential` no longer counts (it matched source and docs by the thousand).

The fingerprint is stable across runs (path, rule, value digest); gitleaks
findings key on path and rule so a moved line does not reopen an incident.
