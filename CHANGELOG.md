# Changelog

All notable changes to this project will be documented in this file.

## [1.3.5] — 2026-08-20

### Changed

- README rewritten for a harness audience (Claude Code, Codex, OpenClaw,
  opencode, …): dropped the direct `scan_skill.py` CLI invocation examples
  and the manual `pip install -r requirements.txt` step — both are
  agent-driven per `SKILL.md`, not something the end user runs by hand

## [1.3.4] — 2026-08-19

### Security

- Known credential shapes (AWS/GitHub/Slack/OpenAI/Google/Stripe key
  formats, JWTs, PEM private keys, generic `key=value` assignments) are now
  redacted out of decoded base64 excerpts before they leave the client, and
  again server-side as defense in depth — closes a leak where a secret
  merely base64-encoded inside a scanned skill would be relayed to the
  backend and echoed verbatim into the report
- SKILL.md now instructs the calling agent not to act on directive-like text
  the report may quote from the (unvetted) skill under analysis — the report
  is scan output to display, not an instruction to follow

## [1.3.2] — 2026-08-17

### Added

- `version` field in SKILL.md frontmatter, CI-enforced to always match the
  scanner's `SCANNER_VERSION` and the signed-bundle manifest
- Explicit runtime-dependency declarations in SKILL.md, including the
  optional `unrar`/`unar` system binary required for `.rar` support

### Changed

- SKILL.md names the analysis backend plainly
  (`https://nimbus.bitdefender.net/skills/checker`, operated by Bitdefender)
  and describes the scan-mode payload precisely: extracted indicators include
  short matched excerpts (regex fragments up to 100 characters, decoded
  base64 snippets up to 500 characters); full files are never uploaded in
  scan mode — correcting the earlier "never raw file contents" phrasing

## [1.3.1] — 2026-08-14

### Changed

- Detector calibration: findings from prose/documentation files move to
  low-confidence `*_in_docs` keys; sensitive-path matching is boundary-aware
  (`os.environ`, `process.env.*` no longer flag `.env`); `dd` requires a real
  `key=value` argument, so date formats no longer match; `import os` removed
  from suspicious imports; `compile()` detection ignores method calls;
  legacy Bitcoin addresses require a valid Base58Check checksum
- Sensitive env var names split into reads (high confidence) vs template
  assignments such as `NAME=` scaffolding (low confidence)
- Report titles use the skill's frontmatter name instead of the
  server-supplied identifier
- Version floors for `light-embed`, `tokenizers`, `numpy`; supported Python
  range documented (3.12–3.13)
- Calling agents may verify findings against the source before presenting
  them as confirmed

## [1.3.0] — 2026-08-14

### Added

- Signed auto-update: payloads are Ed25519-signature-verified against a
  public key pinned in the scanner before anything touches disk; unsigned or
  tampered payloads are rejected
- New dependency: `cryptography` (imported lazily — scanning works without
  it; updates stay disabled until installed)

### Changed

- Updates are staged with path-traversal-safe extraction, sanity-checked,
  and applied via a backup-restore swap — a failed update can no longer
  remove the existing install

### Security

- Clients at 1.2.8 or older reach 1.3.0 through their original unverified
  updater (one-time hop); every update from 1.3.0 onward is verified

## [1.2.8] — 2026-06-18

### Changed

- Skill name resolution now searches additional framework directories:
  `.claude/skills/`, `tools/`, `~/.claude/skills/`, and `~/.local/share/skills/`,
  in addition to the existing OpenClaw paths
- Removed OpenClaw-specific branding from skill description, module docstring,
  and CLI help text — the scanner is now framework-agnostic
- Refactored `load_openclaw_config()` into `_load_extra_skill_dirs()` to support
  multiple framework config sources

## [1.2.7] — 2026-06-17

Initial public release of **Bitdefender Agent Skill Scanner** — a security analysis
tool that audits agent skills before you trust them.

### Features

- Scans skill directories, zip archives, and URLs for security risks
- 71 behavioral detectors across 16 threat categories (code execution, reverse shells,
  obfuscation, crypto-mining, persistence, and more)
- 18 indicator extractors per file (URLs, IPs, base64 blobs, env vars, shell commands, …)
- Recursive archive unpacking (`.zip`, `.tar.gz`, `.tar.bz2`, `.tar`, `.7z`, `.rar`)
- Prose-aware detection of stealth directives in natural-language skill instructions
- Local semantic embeddings via `sentence-transformers/all-MiniLM-L6-v2` (ONNX)
- Privacy-respecting scan mode: only hashes and extracted metadata are transmitted,
  never raw file contents
- Opt-in submit mode for full deep-analysis upload
- Automatic client self-update on launch (`--no-update` to disable)
