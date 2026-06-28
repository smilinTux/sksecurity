# Security Policy — SKSecurity

`sksecurity` is a **security tool** that also handles key material (a sovereign KMS),
so it is held to the crypto bar: read the **honest-claim posture** and the **threat
model** before relying on it or reporting an issue. SKSecurity is, by design, the
ecosystem's **honest-claim auditor** — we hold our own docs to the same rule.

> ⚠️ **Experimental · pre-1.0-posture · NOT independently security-audited.** No
> third-party security audit, fuzzing, or formal review has been performed. The KMS
> binds vetted primitives (pyca `cryptography` — scrypt / HKDF-SHA256 / AES-256-GCM);
> the original code is the scanning, screening, guard, and orchestration logic.
> **Review it yourself before production use.**

---

## Honest claims (what SKSecurity does and does NOT promise)

Per the sk-standards
[CRYPTOGRAPHY_STANDARD](https://github.com/smilinTux/sk-standards), every claim is
scoped to **surface + FIPS number + hybrid-vs-classical**.

- ✅ **The KMS is symmetric/hash and already quantum-acceptable.**
  scrypt → HKDF-SHA256 → AES-256-GCM, DEK `os.urandom(32)`. Grover only halves
  AES-256 to ~128-bit, which is safe — **AES-256 is not "broken" by quantum.**
- ✅ **Local-first, no phone-home.** Every verdict and key wrap stays under
  `~/.sksecurity/`. Threat feeds are opt-in.
- ✅ **Evidence engine.** SKSecurity produces the static crypto inventory + the
  per-channel runtime self-report that makes ecosystem PQC claims evidence-backed.
- ❌ **Not** "quantum-proof," "quantum-safe," "unbreakable," or "CNSA 2.0 compliant."
  Say **"quantum-resistant" / "post-quantum"** and cite the FIPS number + surface.
- ❌ **Not** a KEM, signature scheme, or transport — it does not establish session
  secrets or authenticate peers. It does **nothing** for Harvest-Now-Decrypt-Later on
  bulk content (that is `sk_pqc` + TLS); the KMS has no PQ-relevant asymmetric surface
  to begin with.
- ❌ **Not** a guarantee of safe code. The scanner/screener are heuristic +
  pattern-based defense-in-depth, not a soundness proof — they reduce risk, they do
  not eliminate it.
- ❌ The KMS must **not** become a Shor-vulnerable root: wiring a PGP key as the master
  root re-introduces one and must migrate to a hybrid / SLH-DSA root first.

---

## Threat model

### In scope (what SKSecurity defends)

- **Malicious / risky code before it runs** — multi-layer scan → risk score +
  quarantine over threshold.
- **Hostile input before a model sees it** — prompt-injection, phishing, credential
  leak, malicious link, social engineering, malware payload, data exfiltration.
- **Secret leakage at commit time** — 14 patterns + a pre-commit hook that blocks the
  commit; test-context FP reduction.
- **Key confidentiality at rest** — KMS wraps DEKs under AES-256-GCM with a
  scrypt-sealed master; rotation + immutable audit log.
- **Tamper-evidence** — quarantined artifacts carry SHA256 integrity records; every
  event is recorded in the local audit DB.
- **Claim overreach** — the claim-audit scans docs/marketing for forbidden crypto
  words.

### Out of scope (handle elsewhere)

- **Confidentiality in transit / HNDL on bulk data** — use a hybrid KEM (`sk_pqc`) +
  TLS. SKSecurity is not a transport.
- **Authentication / identity** — use `capauth`. SKSecurity does not prove who a peer
  is.
- **A Shor-resistant asymmetric root** — none exists in SKSecurity today (KMS is
  symmetric/hash). Do not introduce a classical PGP master root.
- **Side channels in the bound primitives** — constant-time/correctness come from pyca
  `cryptography`; SKSecurity does not re-audit them.
- **Completeness of detection** — a determined attacker can evade heuristics; this is
  defense-in-depth, not a proof.

### Trust roots / dependencies

| Surface | Library | Assurance basis |
|---|---|---|
| AES-256-GCM (DEK wrap) | pyca `cryptography` | SP 800-38D; quantum-acceptable (Grover-only) |
| HKDF-SHA256 (key derivation) | pyca `cryptography` | RFC 5869 |
| scrypt (master seal) | pyca `cryptography` | RFC 7914 |
| DEK entropy | `os.urandom(32)` | OS CSPRNG |

SKSecurity **binds** these — it hand-rolls no primitive. Where the ecosystem combines
a hybrid secret it is `HKDF(X25519_ss ‖ MLKEM768_ss)` — concatenate-then-KDF, never
XOR, never pure-PQ.

---

## Supported versions

| Version | Supported |
|---|---|
| 1.2.x | ✅ current |
| < 1.2.0 | ❌ best-effort |

---

## Reporting a vulnerability

**Do not open a public GitHub issue for a security vulnerability.**

- Report privately via **GitHub Security Advisories** ("Report a vulnerability" on the
  Security tab of [`smilinTux/sksecurity`](https://github.com/smilinTux/sksecurity)),
  or
- email the maintainers (smilinTux / SKWorld) at the address on the GitHub org.

Please include: affected version, Python version, a minimal reproduction, and the
relevant config. We aim to acknowledge within **72 hours** and to ship a fix or
mitigation within **90 days**. Credit is given unless you ask otherwise.

### What we especially want to hear about

- A scanner/guard/screener **bypass** that lets a known-bad artifact through clean.
- A **secret pattern miss** (a real credential the guard does not catch) or a path
  where the guard leaks a secret into a log/DB.
- A KMS flaw — DEK recoverable without the master, weak master seal, broken rotation,
  or a tamperable audit log.
- A claim in our own docs/marketing that **overstates** assurance (e.g. a forbidden
  crypto word, or AES-256 implied broken) — we are the auditor; hold us to it.

---

**License:** GPL-3.0-or-later. **Standards:** FIPS 203/204/205 (ML-KEM / ML-DSA /
SLH-DSA, cited for the ecosystem role); SP 800-38D (AES-GCM); RFC 5869 (HKDF);
RFC 7914 (scrypt); NIST CSWP 39 (crypto-agility).
