"""SKStacks per-service PQC posture itemization (df239fe1, deliverable #2).

The ecosystem-wide *per-service* view Chef asked for: enumerate EACH service /
component declared in the SKStacks v2 descriptors (the docker-compose / swarm
stack files) and report its crypto posture, surface by surface:

    * **transport** — TLS on the wire (classical today: X25519/ECDHE + RSA/ECDSA
      certs via Traefik/ACME). HTTPS ≠ quantum-resistant; it is *classical*.
    * **at-rest**   — disk encryption / app-level at-rest crypto (mostly none at
      the service layer; volumes are host-FS).
    * **identity**  — service auth (API keys, JWT, mTLS) — classical or n/a.

Honesty discipline (same as ``pqc_report``): we do NOT assume a service is
secure. A service we can't classify from its descriptor is marked
``unaudited`` (NOT ``n/a``, NOT ``classical`` — explicitly unknown). Many
services are legitimately ``classical`` (TLS), ``symmetric`` (a cache with no
asymmetric crypto), or ``n/a`` (no crypto surface at all) — that is fine and
reported plainly. NOTHING here is quantum-resistant: no SKStacks service has a
PQC transport yet, and we never claim otherwise.

Source of truth = the actual descriptors in ``SKStacks/v2`` (compose/swarm
``services:``). We parse them rather than hard-coding the service list, so the
report tracks the real stack; per-image heuristics + an explicit override map
assign the honest posture, and anything unmatched falls to ``unaudited``.
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Optional

# Posture vocabulary (per-service, transport-focused):
#   classical  — asymmetric crypto on the wire/identity, Shor-breakable (TLS).
#   symmetric  — only symmetric crypto present (AES/SHA) — Grover-only.
#   hybrid-pq  — a PQC/hybrid transport is in place (NONE today — honest zero).
#   n/a        — the service has no crypto surface of its own.
#   unaudited  — could not be classified from the descriptor (UNKNOWN, flagged).
POSTURES = ("classical", "symmetric", "hybrid-pq", "n/a", "unaudited")


def _candidate_stack_roots() -> list[Path]:
    """Where the SKStacks v2 descriptors might live (env override wins)."""
    roots: list[Path] = []
    env = os.environ.get("SKSTACKS_ROOT")
    if env:
        roots.append(Path(env))
    home = Path.home()
    roots += [
        home / "clawd" / "SKStacks",
        home / "clawd" / "skcapstone-repos" / "SKStacks",
        home / "SKStacks",
    ]
    return [r for r in roots if r.exists()]


def _find_stack_files() -> list[Path]:
    """Locate the v2 stack descriptor files (compose/swarm ``services:`` docs)."""
    files: list[Path] = []
    for root in _candidate_stack_roots():
        v2 = root / "v2"
        search = v2 if v2.exists() else root
        for pat in ("*.yml", "*.yaml"):
            for p in search.rglob(pat):
                if "node_modules" in p.parts:
                    continue
                try:
                    text = p.read_text(errors="ignore")
                except Exception:
                    continue
                # A real stack descriptor declares a top-level services: block.
                if re.search(r"(?m)^services:\s*$", text):
                    files.append(p)
        if files:
            break  # first existing root with descriptors wins
    return sorted(set(files))


def _parse_services(text: str) -> list[dict]:
    """Extract ``(service_name, image)`` pairs from a compose/swarm doc.

    Indentation-based (no yaml dep): the ``services:`` block, then 2-space
    keys are service names; we grab each service's ``image:`` if present and
    note whether it declares Traefik TLS labels (→ classical TLS transport).
    """
    lines = text.splitlines()
    out: list[dict] = []
    in_services = False
    cur: Optional[dict] = None
    for ln in lines:
        if re.match(r"^services:\s*$", ln):
            in_services = True
            continue
        if in_services and re.match(r"^[A-Za-z]", ln):
            # left the services block (a new top-level key)
            break
        if not in_services:
            continue
        m = re.match(r"^  ([A-Za-z0-9_.-]+):\s*$", ln)
        if m:
            if cur:
                out.append(cur)
            cur = {"service": m.group(1), "image": "", "tls": False, "raw": []}
            continue
        if cur is not None:
            cur["raw"].append(ln)
            im = re.search(r"image:\s*([^\s#]+)", ln)
            if im and not cur["image"]:
                cur["image"] = im.group(1)
            if "traefik" in ln and ("tls" in ln or "websecure" in ln):
                cur["tls"] = True
    if cur:
        out.append(cur)
    return out


# Explicit, honest per-image posture overrides (substring match on the image or
# service name). Each maps to (transport, at_rest, identity, note). These encode
# what we actually know about the upstream image's crypto surfaces.
_IMAGE_POSTURE: list[tuple[str, dict]] = [
    ("postgres", {
        "transport": "classical", "at-rest": "n/a", "identity": "classical",
        "note": "Postgres: TLS (classical ECDHE/RSA) on the wire if enabled; "
                "SCRAM-SHA-256 password auth (symmetric KDF); no at-rest crypto "
                "(host-FS volume). No PQC.",
    }),
    ("redis", {
        "transport": "classical", "at-rest": "n/a", "identity": "symmetric",
        "note": "Redis: optional TLS (classical) on the wire; AUTH password "
                "(symmetric); RDB/AOF unencrypted on disk. No PQC.",
    }),
    ("open-webui", {
        "transport": "classical", "at-rest": "n/a", "identity": "classical",
        "note": "Open-WebUI: served behind Traefik TLS (classical ECDHE + "
                "RSA/ECDSA ACME cert); JWT session tokens (HMAC, symmetric); "
                "no app-level PQC.",
    }),
    ("litellm", {
        "transport": "classical", "at-rest": "n/a", "identity": "classical",
        "note": "LiteLLM proxy: Traefik TLS (classical); API-key auth; "
                "upstream provider calls over classical TLS. No PQC.",
    }),
    ("infinity", {
        "transport": "classical", "at-rest": "n/a", "identity": "n/a",
        "note": "Infinity embeddings server: internal HTTP (TLS classical if "
                "fronted); no auth/at-rest crypto of its own. No PQC.",
    }),
    ("skfence", {
        "transport": "classical", "at-rest": "unaudited", "identity": "unaudited",
        "note": "skfence app: served over classical TLS; app-level at-rest / "
                "identity crypto not audited from the descriptor — flagged "
                "unaudited (do not assume secure).",
    }),
    ("skpayment", {
        "transport": "classical", "at-rest": "unaudited", "identity": "unaudited",
        "note": "skpayment app: classical TLS transport; payment at-rest + "
                "identity crypto not visible in the descriptor — unaudited.",
    }),
    ("falkordb", {
        "transport": "classical", "at-rest": "n/a", "identity": "symmetric",
        "note": "FalkorDB (graph): optional TLS (classical); password auth; no "
                "at-rest crypto. No PQC. (commented-out in current stack)",
    }),
]


# Service/stack names that should match BEFORE generic image keys (a service may
# reuse a generic image, e.g. skpayment on the open-webui image — its app posture
# wins over the image default).
_NAME_FIRST = ("skfence", "skpayment", "falkordb")


def _classify(svc: dict, stack: str = "") -> dict:
    """Assign an honest per-surface posture to one parsed service."""
    image = (svc.get("image") or "").lower()
    name = svc.get("service", "").lower()
    stack = (stack or "").lower()
    hay = f"{image} {name} {stack}"

    surfaces = None
    # Name/stack-specific overrides win first.
    for nf in _NAME_FIRST:
        if nf in name or nf in stack:
            for key, posture in _IMAGE_POSTURE:
                if key == nf:
                    surfaces = dict(posture)
                    break
            if surfaces is not None:
                break
    # Then image/generic keys.
    if surfaces is None:
        for key, posture in _IMAGE_POSTURE:
            if key in hay:
                surfaces = dict(posture)
                break

    if surfaces is None:
        # Unknown image/service — honest UNKNOWN, not assumed-secure.
        if svc.get("tls"):
            surfaces = {
                "transport": "classical",
                "at-rest": "unaudited",
                "identity": "unaudited",
                "note": "Service declares Traefik TLS (classical transport); "
                        "image/at-rest/identity not in the posture map — flagged "
                        "unaudited.",
            }
        else:
            surfaces = {
                "transport": "unaudited",
                "at-rest": "unaudited",
                "identity": "unaudited",
                "note": "Unrecognized service with no TLS label found in the "
                        "descriptor — crypto posture UNKNOWN (unaudited). Do not "
                        "assume secure.",
            }

    # Roll the per-surface postures up into a single 'worst-honest' posture for
    # the one-line view: unaudited > classical > symmetric > n/a (hybrid-pq only
    # if every crypto surface is hybrid — never true today).
    order = {"unaudited": 4, "classical": 3, "symmetric": 2, "n/a": 1, "hybrid-pq": 0}
    per = [surfaces["transport"], surfaces["at-rest"], surfaces["identity"]]
    roll = max(per, key=lambda p: order.get(p, 4))
    # If everything is n/a, the service genuinely has no crypto surface.
    if all(p == "n/a" for p in per):
        roll = "n/a"

    return {
        "service": svc.get("service"),
        "image": svc.get("image") or "(none)",
        "tls": bool(svc.get("tls")),
        "transport": surfaces["transport"],
        "at_rest": surfaces["at-rest"],
        "identity": surfaces["identity"],
        "posture": roll,
        "quantum_resistant": roll == "hybrid-pq",
        "note": surfaces["note"],
    }


def build_stacks_report() -> dict:
    """Itemize every SKStacks v2 service with its honest crypto posture.

    Returns:
        dict with ``services`` (per-service posture), ``stack_files`` (sources),
        a ``summary`` count per posture, and an ``honest_claim``. Raises only on
        a total inability to find descriptors (the dashboard catches that and
        renders an 'unavailable' marker rather than fabricating a list).
    """
    files = _find_stack_files()
    if not files:
        raise FileNotFoundError(
            "no SKStacks v2 descriptors found (set SKSTACKS_ROOT or place the "
            "repo at ~/clawd/SKStacks)"
        )

    services: list[dict] = []
    stack_files: list[str] = []
    for f in files:
        text = f.read_text(errors="ignore")
        parsed = _parse_services(text)
        if not parsed:
            continue
        # stack label = the app dir under v2/apps or overlays, else filename
        parts = f.parts
        stack = f.stem
        if "apps" in parts:
            stack = parts[parts.index("apps") + 1]
        elif "overlays" in parts:
            stack = "/".join(parts[parts.index("overlays") + 1:])
        stack_files.append(str(f))
        for p in parsed:
            row = _classify(p, stack=stack)
            row["stack"] = stack
            row["stack_file"] = str(f)
            services.append(row)

    counts = {k: 0 for k in POSTURES}
    for s in services:
        counts[s["posture"]] = counts.get(s["posture"], 0) + 1

    total = len(services)
    unaudited = counts.get("unaudited", 0)
    honest = (
        f"{total} SKStacks v2 service(s) itemized across {len(stack_files)} "
        f"descriptor(s). NONE is quantum-resistant: every service transport is "
        f"CLASSICAL TLS (ECDHE/RSA/ECDSA — Shor-breakable) or has no crypto "
        f"surface. Counts: {counts['classical']} classical · "
        f"{counts['symmetric']} symmetric · {counts['n/a']} n/a · "
        f"{unaudited} unaudited (UNKNOWN — flagged, not assumed secure). "
        "PQC has not reached the stack-transport layer (no PQC TLS / hybrid "
        "KEX in Traefik); do not claim any stack service is post-quantum."
    )

    return {
        "report": "pqc-stacks-per-service",
        "stack_files": stack_files,
        "services": services,
        "summary": {"total": total, **counts},
        "honest_claim": honest,
    }


def format_stacks_report(report: Optional[dict] = None) -> str:
    """Render the SKStacks per-service report as text."""
    rpt = report or build_stacks_report()
    L = []
    L.append("🔐🧱 SKStacks Per-Service PQC Posture")
    L.append("=" * 60)
    L.append(f"descriptors: {len(rpt['stack_files'])}")
    for f in rpt["stack_files"]:
        L.append(f"   • {f}")
    L.append("")
    mark = {"hybrid-pq": "✅", "symmetric": "✅", "classical": "⚠️ ",
            "n/a": "·", "unaudited": "❓"}
    for s in rpt["services"]:
        m = mark.get(s["posture"], "❓")
        L.append(f"{m} {s['service']:<22} [{s['posture']:<9}] stack={s['stack']}")
        L.append(f"     image    : {s['image']}")
        L.append(
            f"     surfaces : transport={s['transport']} · "
            f"at-rest={s['at_rest']} · identity={s['identity']}"
        )
        L.append(f"     note     : {s['note']}")
        L.append("")
    sm = rpt["summary"]
    L.append(
        f"Summary: {sm['total']} services · {sm['classical']} classical · "
        f"{sm['symmetric']} symmetric · {sm['n/a']} n/a · "
        f"{sm['hybrid-pq']} hybrid-pq · {sm['unaudited']} unaudited"
    )
    L.append("")
    L.append(f"Honest claim: {rpt['honest_claim']}")
    return "\n".join(L)
