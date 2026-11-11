# Sweep reporting (ITIL)

`sksecurity.report.report(findings, sweep, dry_run=True)` is the one place
every sweep files results. `dry_run=True` (the CLI default) touches nothing;
`sksecurity sweep <name> --report` files.

- Critical finding: own incident, sev2. High: own incident, sev3. Tags:
  `sksecurity`, `sweep:<name>`, `fp:<fingerprint>`, `class:<klass>`,
  `kedb:<id>` when set, plus `host:<host>`.
- Dedup is find-open-first on the `fp:` tag, so a re-run files nothing new and
  appends no event. Incident ids are skcoord's random ids: skcoord only
  derives deterministic ids for its own `service_health` source, so two nodes
  filing the same fingerprint at the same moment can both create one. The
  next run sees both as open; resolve the duplicate by hand.
- At most 20 new per-finding incidents per run. Extra critical/high go into
  the roll-up, which is raised to sev3 with a note.
- Medium and low: ONE open sev4 incident per (sweep, host), titled
  `sksecurity <sweep> sweep on <host>: N medium/low findings`. It is updated
  (a note event) only when the set of findings changes.
- An open finding incident whose fingerprint is absent from a run gets a
  `not seen in sweep at <ts>` event (once), never an auto-close. A truncated
  run (`sweep.truncated`) makes no such claim. Only incidents of the same
  host are annotated.
- Incident text is location, class, rule, host, KEDB id and remediation. Never
  a value.
- One sk-alert per run (`sweep_summary`, level from the worst severity), via
  `sksecurity.integration.alert`.

The ITIL root is `SKSECURITY_ITIL_HOME`, else `SKCAPSTONE_SHARED_ROOT`, else
`~/.skcapstone`. skcoord (or skcapstone) is optional: without it a non-dry run
returns `error: itil-unavailable` and files nothing.

## Baseline (accepted backlog)

The first real run of a sweep on a node finds a large pre-existing backlog.
Filing it would flood ITIL (one incident per critical/high finding), so a
backlog is accepted once and only NEW findings are filed afterwards.

    sksecurity sweep fs --baseline               # record the baseline, file nothing
    sksecurity sweep fs --baseline --report      # record it and file ONE backlog incident
    sksecurity sweep fs --report                 # daily: only fingerprints outside the baseline

- File: `~/.local/state/sksecurity/baseline-<sweep>.json` (override the directory with
  `SKSECURITY_STATE_DIR`), mode 0600, per sweep and per host (it is a local file).
  It holds fingerprints with klass, severity and first_seen. No locations, no values.
- Backlog incident: ONE sev3 per (sweep, host), titled
  `sksecurity <sweep> backlog on <host>: N accepted findings`, tags `sksecurity`,
  `sweep:<name>`, `host:<h>`, `backlog`. The body is counts by severity and class and the top
  20 locations.
- With a baseline, `--report` skips baselined fingerprints (per-finding incidents, the 20-per-run
  cap and the medium/low roll-up all apply to new findings only). Run summaries show `new` and
  `baselined`. The CLI exit status is 1 only for a new critical/high finding.
- When accepted findings disappear (fixed), a non-dry `--report` appends one event to the open
  backlog incident (how many were fixed, how many remain, by severity and class) and drops them
  from the baseline, so a recurrence is reported as new. A truncated run drops nothing.
  The backlog incident is never auto-closed.
- Meta findings (`tool.*`, `sweep.*`) are never baselined.
- Dry run (`--dry-run`, default) never prunes the baseline and files nothing.

### Re-baselining

After a clean-up, a sweep config change or a new fleet node, run a full (untruncated) sweep and
`sksecurity sweep <name> --baseline --report`. It replaces the baseline with the current findings
(`first_seen` is kept for fingerprints already accepted) and appends a "re-baselined" event to the
open backlog incident instead of filing a second one. To start over, delete the baseline file and
resolve the old backlog incident by hand. Do not baseline a run that reported `sweep.truncated`.
