# Honest-Claims Scanner — the no-overclaim gate

`sksecurity claims` is the SK ecosystem's mechanical guard against security
**overclaims**. It scans docs, code, and comments for absolute promises the
math cannot keep, and exits non-zero when it finds a real one. CI runs it on
every push and pull request (`.github/workflows/honest-claims.yml`).

The rule it enforces (from the sk-standards `CRYPTOGRAPHY_STANDARD`):

> Claims must match the math. A classical KEM stays harvest-now-decrypt-later
> (HNDL) exposed forever — nothing classical is `quantum-proof`. A hybrid
> scheme is only as strong as its **strongest surviving leg**; it is not
> `unbreakable`, it degrades to whichever leg holds. Cite the standard
> (FIPS 203 / 204 / 205), not the adjective.

## What it flags

| Forbidden phrase | Why it is a lie | Say instead |
| --- | --- | --- |
| `quantum-proof` | No classical primitive resists a CRQC; HNDL is forever | "post-quantum" / "quantum-resistant", name the KEM |
| `quantum-safe` | Implies a proven guarantee no scheme gives | "post-quantum", cite FIPS 203 (ML-KEM) |
| `unbreakable` | Security is a work factor, not a guarantee | the algorithm + level (e.g. AES-256, ML-KEM-768) |
| `uncrackable` | An absolute no real system meets | the concrete threat model / work factor |
| `100% secure` | You bound risk, you do not eliminate it | "reduces risk", "defense in depth" + the controls |
| `military-grade` (as a security claim) | Marketing pedigree, not a spec | the primitive + parameters (AES-256-GCM, X25519) |

`military-grade` is only flagged when the same line also talks about security
or crypto — "military-grade titanium" is a materials claim and passes.

## What it deliberately allows

The gate is built to be honest, not pedantic. It does **not** fire on:

- **Negations** — "we never say quantum-proof", "no cipher is truly
  unbreakable", "nothing is 100% secure". The negating word is detected
  anywhere in the enclosing sentence (before or after the phrase).
- **Quoted / meta references** — a token wrapped in quotes or backticks, e.g.
  a policy that forbids `"unbreakable"`, or a test fixture
  `_FORBIDDEN = ("quantum-proof", ...)`.
- **Inline directives** — append `# honest-claims: allow` (or
  `# noqa: honest-claims`) to a line to suppress just that line.
- **Allowlisted files** — globs/paths listed in `.honestclaims-allow` are
  skipped entirely. Reserve this for files that must carry raw forbidden
  phrases as data (test fixtures, the scanner's own pattern table) — not for
  hiding real marketing copy.

## Usage

```bash
# Scan a tree (CI default) — exits 1 on a real violation
sksecurity claims scan .

# Scan one file, JSON output
sksecurity claims scan README.md --format json

# Quick one-liner check
sksecurity claims text "we never promise unbreakable crypto"   # exit 0
```

As a library:

```python
from sksecurity.honest_claims import HonestClaimsScanner

scanner = HonestClaimsScanner(allowlist_file=".honestclaims-allow")
result = scanner.scan_directory("docs")
if result.has_violations:
    print(result.format_report())
    raise SystemExit(1)
```

## How negation detection works (and its limits)

The scanner scopes to the sentence around each match (bounded by `.`, `!`,
`?`, or a blank line) and treats the phrase as honest if that sentence
contains a negation/meta word (never, not, no, avoid, forbid, false, myth,
"no such thing", `❌`, …) — or if the phrase is immediately wrapped in a
quote. This is a heuristic, not a parser: a positive claim that merely follows
an unrelated negation in the *same* sentence could be missed, and a contrived
negation could suppress a real claim. When in doubt, prefer the inline
directive or an allowlist entry, and keep claims specific enough that the
question never comes up.

## Files

- `sksecurity/honest_claims.py` — scanner library (patterns + detection)
- `tests/test_honest_claims.py` — TDD suite (detect / negate / allowlist)
- `.honestclaims-allow` — repo allowlist (test fixtures only)
- `.github/workflows/honest-claims.yml` — CI gate
