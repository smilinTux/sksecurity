# Mail sweep and `screen-file`

Screens mail that is already on disk. It does not talk to Gmail and it never
changes, moves or deletes a file it inspects.

## `sksecurity screen-file PATH... [--format json]`

Report-only verdict per file (safe, suspicious, malicious). Exit 1 if any file
is malicious. Directories are walked, symlinks are not followed.

| Check | Result |
|---|---|
| ClamAV (`clamdscan` when a clamd socket exists, else `clamscan --no-summary --infected`) | detection is malicious. If neither is installed the verdict records `av: unavailable` and the other checks still run. Many files share one AV invocation. |
| Dangerous and double extensions | same rules as the email screener (`.exe`, `.js`, `invoice.pdf.exe`) |
| Magic bytes against extension | a PE, ELF or Mach-O named `.pdf` (or anything not an executable type) is malicious |
| Office macros | OOXML zip with `vbaProject.bin` is high; legacy OLE `.doc/.xls/.ppt` is medium ("may contain macros") |
| Zip archives | members are listed, never extracted, and the extension rules apply to each member; an encrypted zip is medium |

Library use: `sksecurity.filescreen.screen_file(path)` returns a `FileVerdict`
(`.verdict`, `.findings`, `.av`, `.to_dict()`); `screen_files(paths)` does the
same with a single AV pass.

## Link and subject screening (`EmailScreener`)

Signals added for links: URL shorteners (a bare shortener is a weak signal),
punycode/IDN hostnames (`xn--`), lookalike brand domains (paypal, google,
microsoft, apple, amazon, gmail, usaa, chase, wellsfargo in a hostname that is
not that brand's own domain), and "click URL to verify" phrasing. The subject
line is now screened for urgency patterns as well as the body.

## `sksecurity sweep mail --opt dir=PATH`

Screens every file in `dir` plus any `.eml` messages. Attachments inside an
`.eml` are written to a private temp dir for screening and removed afterwards.

| Class | Meaning |
|---|---|
| `mail.malware` | AV detection |
| `mail.macro` | Office macros (definite or possible) |
| `mail.dangerous-attachment` | dangerous or double extension, disguised executable, bad archive member, encrypted zip |
| `mail.phish-link` | phishing link or language in a message that did not screen as safe |

`location` is the file path, or `<message-id>` / `<message-id>#<attachment>` for
messages. Findings never contain message bodies or URLs. The fingerprint is
stable across runs (location, rule and a content hash).
