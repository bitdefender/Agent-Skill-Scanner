# Changelog

All notable changes to this project will be documented in this file.

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
