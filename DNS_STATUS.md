# DNS & Domain Status

> **Status as of 2026-04-29:** Custom domains (`sksecurity.com`, `sksecurity.io`,
> `install.sksecurity.com`, `docs.sksecurity.io`) are **not registered or configured**.
> All working URLs point to GitHub. This file documents that reality and the plan to
> close the gap.

---

## Working URLs (use these now)

| Purpose | URL |
|---------|-----|
| Repository | https://github.com/smilinTux/sksecurity |
| Install script | https://raw.githubusercontent.com/smilinTux/SKSecurity/main/install.sh |
| Documentation | https://github.com/smilinTux/SKSecurity/tree/main/docs |
| Issues | https://github.com/smilinTux/SKSecurity/issues |
| Community | https://discord.gg/5767MCWbFR |
| Support | support@smilintux.org |

### Install command (current)

```bash
curl -sSL https://raw.githubusercontent.com/smilinTux/SKSecurity/main/install.sh | bash
```

---

## Broken references to remove from docs

The following domains appear in older documentation but resolve to nothing:

- `install.sksecurity.com` — not configured
- `docs.sksecurity.io` — not configured
- `sksecurity.com` — not registered
- `sksecurity.io` — not registered

Replace any occurrence with the GitHub equivalents listed above.

---

## DNS setup plan (future work)

When domains are purchased, the recommended layout is:

| Record | Target |
|--------|--------|
| `sksecurity.io` | Marketing landing page |
| `install.sksecurity.io` | Redirect → GitHub raw installer |
| `docs.sksecurity.io` | GitHub Pages docs site |

Options in preference order:

1. **Register `sksecurity.io`** — most concise, matches package name
2. **Use `security.smilintux.org` subdomains** — no new domain cost
3. **Use GitHub Pages** — `smilinTux.github.io/SKSecurity` — zero cost

Update this file once DNS is live.
