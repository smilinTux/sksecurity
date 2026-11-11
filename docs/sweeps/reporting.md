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
