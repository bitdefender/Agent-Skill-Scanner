# Bitdefender Agent Skill Scanner

**Cloud-backed security analysis for agent skills.**

Agent skills are executable code plus natural-language instructions that run with your agent's privileges. A single malicious or careless skill can exfiltrate secrets, open a reverse shell, mine cryptocurrency, phone home, or hide a delayed trigger. Bitdefender Agent Skill Scanner audits a skill *before* you trust it.

It walks every file in a target skill, extracts security indicators, runs **71 behavioral detectors across 16 threat categories**, recursively unpacks nested archives, hashes everything, and sends the extracted metadata to Bitdefender's analysis backend, which returns an **LLM-generated security report** with a risk level, a summary, and per-file findings.

> A scan that returns no findings means no known threat patterns were detected — not that the skill is safe.

---

## What it detects

**16 behavioral categories / 71 patterns:**

| Category | Examples |
| --- | --- |
| Code execution | `eval`/`exec`, dynamic `__import__`, JS `Function()`, PowerShell `Invoke-Expression` |
| Subprocess usage | `shell=True`, `os.system`, `os.popen` |
| Obfuscation | base64-decode-then-exec, hex decoding, `chr()` construction, known encoded payloads |
| Network | `requests`/`httpx`/`urllib`, raw sockets, `fetch()`, connections to raw IPs |
| File operations | writes, deletions, bulk `shutil` ops, destructive `rm -rf` |
| Crypto-mining | xmrig/stratum/mining-pool indicators |
| Reverse shells | `/dev/tcp`, `nc -e`, `bash -i >&`, `pty.spawn` |
| Download-and-execute | `curl … \| sh`, pip/npm install from URL, `npx` without approval |
| Credential access | bulk environment-variable harvesting |
| System persistence | cron, systemd, launchd, Windows registry run-keys |
| Privilege escalation | `sudo`, dangerous `chmod`, `chown root`, writes to system paths |
| Path traversal | `../../..`, URL-encoded traversal |
| Telemetry | analytics/tracking SDKs, `sendBeacon`, phone-home |
| Symlink attacks | `ln -s`, `os.symlink`, Node `fs.symlink` |
| Time bombs | date/timestamp-comparison triggers, delayed execution |
| Stealth directives | natural-language exfiltration, covert-action, and hidden-memory instructions |

**18 indicator types** are extracted from every text file: URLs, IPv4 addresses, data/`javascript:` URIs, emails, base64 blobs (decoded and inspected), percent-encoded URLs, environment-variable references, **25 dangerous shell commands**, sensitive file paths, suspicious imports, private/loopback IPs, crypto-wallet addresses, known secret env-var names, paste-service domains, DNS-exfiltration patterns, and invisible Unicode characters.

**Structural checks:** hidden dotfiles, package install-hooks (`preinstall`/`postinstall`, setup.py `cmdclass`), file hashing (SHA-256 + MD5), and a normalized skill-level hash used for report caching.

## Highlights

- **Layered analysis** — local indicator extraction feeds a server-side LLM that produces the report.
- **Deep archive inspection** — recursively unpacks `.zip`, `.tar.gz`/`.tgz`, `.tar.bz2`/`.tbz2`, `.tar`, `.7z`, and `.rar` up to 10 levels deep, with limits of 500 MB uncompressed and 10,000 entries per archive. Symlinks are skipped, never followed.
- **Prose-aware** — natural-language threats hidden in `SKILL.md` instructions (stealth exfiltration, covert actions, keyword/counter triggers) are first-class detections.
- **Semantic embeddings** — computes local sentence embeddings (`sentence-transformers/all-MiniLM-L6-v2`, ONNX) to support analysis; can be disabled.
- **Privacy-respecting default** — in scan mode, only hashes, extracted indicators, and metadata are transmitted; full files are never uploaded. Indicators include short matched excerpts (regex match fragments up to 100 characters, decoded base64 snippets up to 500 characters). Full-archive upload happens only in the explicit, opt-in submit mode.
- **Flexible targets** — scan a directory, an installed skill by name, a `.zip`, or a URL.

## Installation

This is an agent skill for use inside a harness — Claude Code, Codex, OpenClaw, opencode, or similar. It is not a standalone CLI tool. Requires Python 3.12 or 3.13 (3.13 recommended). Place it in the harness's skills directory (e.g. `~/.claude/skills/`, `~/.openclaw/skills/`, or your project's `skills/`) — the skill installs its own dependencies on first use.

**Dependencies:** `requests`, `pyyaml`, `py7zr`, `rarfile`, `light-embed`, `tokenizers`, `numpy`, `cryptography`. Optional pieces degrade gracefully — `py7zr`/`rarfile` are only needed for `.7z`/`.rar` targets, `light-embed`/`tokenizers`/`numpy` only for embeddings, and `cryptography` only for verifying signed self-updates (without it, scanning works and updates stay disabled).

> `.rar` extraction also requires a system `unrar`/`unar` binary on your `PATH` (a requirement of the `rarfile` library).

## Usage

There is no separate command to learn. Once installed, ask your agent in plain language — *"scan the foo skill for security risks"* — and the harness handles invocation, target resolution, and update checks per the skill's own instructions (`SKILL.md`), then presents the report.

Two modes, both agent-driven:

- **Scan (default) — metadata only.** A casual request always uses this mode; local extraction feeds a backend LLM report, and full files are never uploaded.
- **Submit — full deep analysis (opt-in).** Uploads the **complete skill archive** for deeper backend analysis. Asynchronous: the agent submits, then a later scan request retrieves the finished report. The agent won't do this unless you explicitly ask for it.

Example report:

```text
# Skill Scan: my-skill

- **Severity:** CLEAN
- **Scan Date:** 2026-06-15

No security findings detected.
```

### Target types

You can refer to a target however is natural — the skill resolves it:

| Target | Behavior |
| --- | --- |
| Directory path | Scanned directly as the skill root. |
| Skill name | Resolved via the harness's known skill directories (project- and user-level), plus any extra directories from framework config. |
| `.zip` archive | Extracted to a temp directory, then scanned. |
| URL | Sent to the backend for scanning (scan mode only). |

## How the agent behaves

When you ask in plain language, the skill holds the agent to a fixed contract:

- **Scan mode is the default** — a casual request never uploads your files.
- **Submit is opt-in only** — the agent won't upload the full archive unless you explicitly ask.
- **The agent relays, it doesn't overrule** — it presents the backend's report and never substitutes its own verdict; it may verify individual findings against the skill's source and mark which ones it confirmed.
- **Errors are surfaced as-is** — on failure (server unreachable, analysis failed) you get the specific reason.
- **Sessions reset after a self-update** — if the client updated on launch, the agent asks you to start a fresh session so the new version runs.

## How it works

1. **Resolve** the target into a skill root (extracting a zip to a temp dir if needed).
2. **Pack & hash** the skill into a normalized archive and compute its skill-level SHA-256.
3. **Cache check** — ask the server whether a report already exists for that hash; if so, return it immediately.
4. **Collect & enrich** — walk every file, hash it, recurse into archives, and run all 18 indicator extractors and 71 behavioral patterns over text content.
5. **Embed** — compute local semantic embeddings (unless disabled).
6. **Submit metadata** — send hashes, indicators (with their short matched excerpts), counts, metadata, and embeddings to the backend. No full file contents in scan mode.
7. **Report** — the backend returns a risk level, summary, and findings, rendered as Markdown.

## What gets sent to the server

| Mode | Transmitted |
| --- | --- |
| **Scan** (default) | File hashes (SHA-256/MD5), extracted indicators and pattern matches — including short excerpts of matched content (regex fragments ≤100 chars, decoded base64 snippets ≤500 chars) — file metadata (path, size, MIME), finding counts, `SKILL.md` frontmatter, dependency metadata, and local embeddings. **Full file contents are *not* transmitted.** |
| **Submit** (opt-in) | The complete skill archive is uploaded for deep analysis. |

## Updates

By default, on every run the client contacts the server and — if a newer version exists — downloads it and applies it **only after verifying its Ed25519 signature** against a public key pinned in the client. The update is staged with path-traversal-safe extraction, sanity-checked, and swapped in with an automatic backup-restore on failure, so a bad or tampered update can neither run nor destroy the existing install. The client then re-executes; one practical implication is that the exact client code that runs may change between invocations. If an update is applied mid-session, start a new session so the new version loads.

---

## Legal & Privacy

By using Bitdefender Agent Skill Scanner, you confirm that you are over 16 years old and you have read and agreed to Bitdefender's [End User License Agreement](https://www.bitdefender.com/en-us/site/view/subscription-agreement-and-terms-of-services-for-home-user-solutions) and [Privacy Policy](https://www.bitdefender.com/en-us/site/view/legal-privacy-policy-for-home-users-solutions).
