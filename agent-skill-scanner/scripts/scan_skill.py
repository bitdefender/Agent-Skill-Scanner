#!/usr/bin/env python3
"""Agent Skill Scanner — security analysis for agent skills."""

import argparse
import base64
import hashlib
import io
import json
import mimetypes
import os
import platform
import re
import shutil
import sys
import tempfile
import time
import zipfile
import tarfile
from pathlib import Path

import requests
import yaml

_SCRIPT_DIR = Path(__file__).resolve().parent
if str(_SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(_SCRIPT_DIR))

from embeddings import compute_embeddings

try:
    import py7zr

    HAS_7Z = True
except ImportError:
    HAS_7Z = False

try:
    import rarfile

    HAS_RAR = True
except ImportError:
    HAS_RAR = False

SCANNER_VERSION = "1.3.1"

MAX_EXTRACT_BYTES = 500 * 1024 * 1024   # 500 MB total uncompressed size
MAX_EXTRACT_FILES = 10_000               # max entries per archive
DEFAULT_SERVER_URL = "https://nimbus.bitdefender.net/skills/checker"
_SKILL_DIR = _SCRIPT_DIR.parent


def _parse_version(v: str) -> tuple[int, ...]:
    return tuple(int(x) for x in v.strip().split("."))


# Base64 of the raw 32-byte Ed25519 public key used to verify update payloads.
# Pinned at release time by nimbus_tools/sign_scanner_bundle.py --generate-keypair.
UPDATE_PUBKEY_B64 = "5XWSjd1am9OAu8uLCn+dIouQtKt+3dzQ+9wWQCUWWXQ="


def _update_canonical_message(version: str, sha256_hex: str) -> bytes:
    """Canonical byte string signed by the release tool and verified by clients."""
    return f"bd-skill-scanner\n{version}\n{sha256_hex}\n".encode("utf-8")


def _verify_update_payload(
    zip_bytes: bytes,
    version: str,
    sha256_hex: str,
    signature_b64: str,
    pubkey_b64: str,
) -> tuple[bool, str]:
    """Verify a downloaded update bundle before it is allowed to touch disk.

    Checks the recomputed SHA-256 against the served digest, then the Ed25519
    signature over the canonical message. The cryptography import is lazy so
    installs that predate the dependency keep scanning (updates just stay off).
    """
    if not pubkey_b64:
        return False, "no pinned update public key in this build"
    actual_hex = hashlib.sha256(zip_bytes).hexdigest()
    if actual_hex != sha256_hex:
        return False, f"payload hash mismatch (expected {sha256_hex}, got {actual_hex})"
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    except ImportError:
        return False, (
            "signature verification unavailable; "
            "run `pip install -r requirements.txt` to re-enable updates"
        )
    try:
        pubkey = Ed25519PublicKey.from_public_bytes(base64.b64decode(pubkey_b64))
        pubkey.verify(
            base64.b64decode(signature_b64),
            _update_canonical_message(version, actual_hex),
        )
    except InvalidSignature:
        return False, "payload failed signature verification — possible tampering"
    except Exception as exc:
        return False, f"signature verification error: {exc}"
    return True, ""


_RE_STAGED_VERSION = re.compile(r'^SCANNER_VERSION\s*=\s*"([^"]+)"', re.MULTILINE)


def _stage_update_zip(zip_bytes: bytes, staging_parent: Path) -> Path:
    """Extract an update bundle into a fresh staging dir using safe extraction."""
    staging = Path(tempfile.mkdtemp(prefix=".bd_scanner_staging-", dir=staging_parent))
    try:
        with zipfile.ZipFile(io.BytesIO(zip_bytes)) as zf:
            _safe_zip_extract(zf, staging)
    except Exception:
        shutil.rmtree(staging, ignore_errors=True)
        raise
    return staging


def _staged_version(staged_root: Path) -> str:
    """Read SCANNER_VERSION out of a staged bundle without importing it."""
    script = staged_root / "scripts" / "scan_skill.py"
    try:
        m = _RE_STAGED_VERSION.search(script.read_text(encoding="utf-8", errors="replace"))
        return m.group(1) if m else ""
    except OSError:
        return ""


def _swap_install(skill_dir: Path, staged_root: Path, version: str) -> None:
    """Replace skill_dir with staged_root, restoring the original on any failure."""
    backup = skill_dir.parent / f".bd_scanner_backup-{version}"
    if backup.exists():
        shutil.rmtree(backup)
    skill_dir.rename(backup)
    try:
        try:
            staged_root.rename(skill_dir)
        except OSError:
            shutil.copytree(staged_root, skill_dir)
    except Exception:
        shutil.rmtree(skill_dir, ignore_errors=True)
        try:
            backup.rename(skill_dir)
        except OSError:
            try:
                shutil.copytree(backup, skill_dir, dirs_exist_ok=True)
            except Exception:
                print(f"  [WARN] Could not restore previous install; backup preserved at {backup}",
                      file=sys.stderr)
                raise
        raise
    shutil.rmtree(staged_root, ignore_errors=True)  # leftover only on the copytree path
    shutil.rmtree(backup, ignore_errors=True)


def _check_and_apply_update(server_url: str, skill_dir: Path | None = None) -> bool:
    """Check the server for a newer scanner version; verify, stage, and apply it.

    The install is never modified before a signature-verified staged copy
    exists. Every failure prints a specific warning, returns False, and lets
    the scan proceed. Returns True only right before os.execv.
    """
    skill_dir = skill_dir or _SKILL_DIR
    base = server_url.rstrip("/")

    try:
        resp = requests.post(f"{base}/scanner/version", timeout=5)
        resp.raise_for_status()
        manifest = resp.json()
        remote_version = manifest.get("version", "")
        if not remote_version:
            print("  [WARN] Update check failed: server response has no version field.",
                  file=sys.stderr)
            return False
    except Exception as exc:
        print(f"  [WARN] Update check failed: {exc}", file=sys.stderr)
        return False

    try:
        remote_tuple = _parse_version(remote_version)
        local_tuple = _parse_version(SCANNER_VERSION)
    except (ValueError, AttributeError):
        print(f"  [WARN] Could not parse version strings (remote={remote_version!r}, "
              f"local={SCANNER_VERSION!r})", file=sys.stderr)
        return False

    if remote_tuple <= local_tuple:
        print(f"  Scanner is up to date ({SCANNER_VERSION}).", file=sys.stderr)
        return False

    sha256_hex = manifest.get("sha256", "")
    signature_b64 = manifest.get("signature", "")
    if not sha256_hex or not signature_b64:
        print("  [WARN] Update skipped: server did not provide a signed manifest.",
              file=sys.stderr)
        return False

    print(f"  New version available: {remote_version} (current: {SCANNER_VERSION}). "
          f"Downloading update...", file=sys.stderr)

    try:
        dl = requests.post(f"{base}/scanner/download", timeout=30)
        dl.raise_for_status()
    except Exception as exc:
        print(f"  [WARN] Failed to download update: {exc}", file=sys.stderr)
        return False

    ok, reason = _verify_update_payload(
        dl.content, remote_version, sha256_hex, signature_b64, UPDATE_PUBKEY_B64
    )
    if not ok:
        print(f"  [WARN] Update rejected: {reason}", file=sys.stderr)
        return False

    staging = None
    try:
        staging = _stage_update_zip(dl.content, skill_dir.parent)
        staged_ver = _staged_version(staging)
        if staged_ver != remote_version:
            print(f"  [WARN] Update rejected: staged bundle reports version "
                  f"{staged_ver!r}, server claimed {remote_version!r}.", file=sys.stderr)
            return False
        _swap_install(skill_dir, staging, remote_version)
        staging = None  # consumed by the swap (renamed) or already copied
    except Exception as exc:
        print(f"  [WARN] Failed to apply update ({exc}); existing install left intact.",
              file=sys.stderr)
        return False
    finally:
        if staging is not None and staging.exists():
            shutil.rmtree(staging, ignore_errors=True)

    print(f"  Updated to {remote_version}. Restarting...", file=sys.stderr)
    os.execv(sys.executable, [sys.executable] + sys.argv)
    return True


# Keys from the server response to include in stdout for the LLM.
# Edit this list to control what the calling agent sees.
REPORT_KEYS = [
    "skill_name",
    "scan_date",
    "adjusted_risk_level",
    "risk_level",
    "llm_summary",
    "findings",
]

# Appended to formatted output when the server marks the report as metadata-only.
METADATA_DEEP_ANALYSIS_NOTICE = (
    "**Metadata-only scan.** For a better result, ask the agent to submit the skill archive for deep analysis."
)

# Displayed once on first use.
_TERMS_NOTICE = (
    "\n---\n"
    "By using Bitdefender Skill Scanner you agree to "
    "[Terms of Service](https://www.bitdefender.com/en-us/site/view/subscription-agreement-and-terms-of-services-for-home-user-solutions) "
    "and [Privacy Policy](https://www.bitdefender.com/en-us/site/view/legal-privacy-policy-for-home-users-solutions)."
)


def _terms_marker_path() -> Path:
    return Path.home() / ".bitdefender" / "skill_scanner" / ".terms_accepted"


def _show_terms_notice_once() -> None:
    """Print the ToS/Privacy notice on first use and persist acceptance."""
    marker = _terms_marker_path()
    if not marker.exists():
        print(_TERMS_NOTICE)
        try:
            marker.parent.mkdir(parents=True, exist_ok=True)
            marker.touch()
        except OSError:
            pass

ARCHIVE_EXTENSIONS = {
    ".zip",
    ".tar.gz",
    ".tgz",
    ".tar.bz2",
    ".tbz2",
    ".tar",
    ".7z",
    ".rar",
}

# ---------------------------------------------------------------------------
# Regex patterns
# ---------------------------------------------------------------------------

RE_URL = re.compile(
    r"(?:https?|ftp|ftps|sftp|smtp|pop3|imap|ssh|git|svn|smb|telnet|ldaps?|gopher|ws|wss)"
    r"://[^\s<>\"')\]]+"
)
RE_DATA_URI = re.compile(r"data:[a-zA-Z0-9]+/[a-zA-Z0-9.+\-]+(?:;[a-zA-Z0-9=]+)*,[A-Za-z0-9+/=]+")
RE_JAVASCRIPT_URI = re.compile(r"javascript:\S+", re.IGNORECASE)
RE_IPV4 = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
)
RE_BASE64 = re.compile(r"\b[A-Za-z0-9+/]{20,}={0,2}(?![A-Za-z0-9+/=])")
RE_ENCODED_URL = re.compile(r"(?:%[0-9A-Fa-f]{2}){3,}")
RE_EMAIL = re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}")
RE_ENV_VAR = re.compile(
    r"""(?:"""
    r"""\$\{[A-Z_][A-Z0-9_]*\}"""  # ${VAR}
    r"""|\$[A-Z_][A-Z0-9_]*"""  # $VAR
    r"""|os\.environ\s*[\[(]"""  # os.environ[ or os.environ(
    r"""|process\.env\.[A-Z_]"""  # process.env.VAR
    r""")""",
    re.VERBOSE,
)

# High-recall name matching by design: quoted invocations (os.system("…"),
# subprocess list args) must stay detectable, and documentation mentions are
# already down-weighted via the *_in_docs split. dd alone requires a
# key=value argument — real dd invocations always have one, date formats
# ("dd-MM-yyyy", "yyyy-mm-dd") never do.
DANGEROUS_COMMANDS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"\bcurl\b"), "curl"),
    (re.compile(r"\bwget\b"), "wget"),
    (re.compile(r"\bnc\b"), "nc"),
    (re.compile(r"\bncat\b"), "ncat"),
    (re.compile(r"\bnetcat\b"), "netcat"),
    (re.compile(r"\bssh\b"), "ssh"),
    (re.compile(r"\bscp\b"), "scp"),
    (re.compile(r"\brsync\b"), "rsync"),
    (re.compile(r"\bchmod\b"), "chmod"),
    (re.compile(r"\bchown\b"), "chown"),
    (re.compile(r"\brm\s+-rf\b"), "rm -rf"),
    (re.compile(r"\bdd\s+(?:if|of|bs|count|seek|skip|conv|status)="), "dd"),
    (re.compile(r"\bmkfs\b"), "mkfs"),
    (re.compile(r"\bmount\b"), "mount"),
    (re.compile(r"\bumount\b"), "umount"),
    (re.compile(r"\biptables\b"), "iptables"),
    (re.compile(r"\bnmap\b"), "nmap"),
    (re.compile(r"\bsocat\b"), "socat"),
    (re.compile(r"\btelnet\b"), "telnet"),
    (re.compile(r"\bftp\b"), "ftp"),
    (re.compile(r"\btftp\b"), "tftp"),
    (re.compile(r"\bbase64\s+-d\b"), "base64 -d"),
    (re.compile(r"\bbase64\s+--decode\b"), "base64 --decode"),
    (re.compile(r"\bopenssl\b"), "openssl"),
    (re.compile(r"\bgpg\b"), "gpg"),
]

SENSITIVE_PATHS = [
    "/etc/passwd",
    "/etc/shadow",
    "/etc/hosts",
    "/etc/sudoers",
    "~/.ssh/",
    "~/.aws/",
    "~/.gnupg/",
    "~/.config/",
    "~/.netrc",
    "~/.bashrc",
    "~/.zshrc",
    "~/.profile",
    "~/.bash_history",
    "/proc/self/",
    "/dev/tcp/",
    "/dev/udp/",
    "id_rsa",
    "id_ed25519",
    "credentials.json",
    "service_account.json",
    ".env",
]


def _sensitive_path_pattern(sp: str) -> re.Pattern:
    """Path-boundary regex for a sensitive-path entry.

    Bare substring matching flagged ``.env`` inside ``os.environ`` and
    ``id_rsa`` inside identifiers. Entries not starting with a path prefix
    get a leading boundary; entries not ending in ``/`` get a trailing one
    (which is what rejects ``os.environ`` — the ``i`` after ``.env``).
    """
    prefix = "" if sp[0] in "/~." else r"(?<!\w)"
    suffix = "" if sp.endswith("/") else r"(?!\w)"
    if sp == ".env":
        # process.env.X / import.meta.env.X / Deno.env.get(...) etc. are
        # member access, not env files; config.env / .env.production still
        # match. os.environ is rejected by the trailing (?!\w) — "iron"
        # continues the word.
        prefix = (r"(?<!process)(?<!meta)(?<!Deno)(?<!deno)(?<!window)"
                  r"(?<!this)(?<!self)(?<!globalThis)(?<!Bun)(?<!bun)")
        suffix = r"(?!\.example)" + suffix
    return re.compile(prefix + re.escape(sp) + suffix)


SENSITIVE_PATH_PATTERNS: list[tuple[str, re.Pattern]] = [
    (sp, _sensitive_path_pattern(sp)) for sp in SENSITIVE_PATHS
]

# NOTE: `import os` / `from os import` are deliberately absent — they appear
# in essentially every non-trivial Python file and carry no signal on their
# own; the dangerous os usages (os.system/os.popen/os.exec*) are covered by
# SECURITY_PATTERNS and the os.exec pattern below.
SUSPICIOUS_IMPORT_PATTERNS = [
    re.compile(r"\bimport\s+subprocess\b"),
    re.compile(r"\bfrom\s+subprocess\s+import\b"),
    re.compile(r"\bos\.exec"),
    re.compile(r"""require\s*\(\s*['"]child_process['"]\s*\)"""),
    re.compile(r"""require\s*\(\s*['"]net['"]\s*\)"""),
    re.compile(r"""require\s*\(\s*['"]dgram['"]\s*\)"""),
    re.compile(r"""require\s*\(\s*['"]fs['"]\s*\)"""),
    re.compile(r"\bimport\s+ctypes\b"),
    re.compile(r"\bfrom\s+ctypes\s+import\b"),
    re.compile(r"\bimport\s+http\.server\b"),
    re.compile(r"\bfrom\s+http\.server\s+import\b"),
    re.compile(r"\bimport\s+BaseHTTPServer\b"),
    re.compile(r"\bimport\s+pickle\b", re.IGNORECASE),
    re.compile(r"\bfrom\s+pickle\s+import\b", re.IGNORECASE),
    re.compile(r"\bimport\s+marshal\b"),
    re.compile(r"\bfrom\s+marshal\s+import\b"),
    re.compile(r"\bimport\s+shelve\b"),
]

SCRIPT_EXTENSIONS = {
    ".py", ".js", ".ts", ".jsx", ".tsx", ".sh", ".bash",
    ".rb", ".pl", ".lua", ".ps1", ".bat", ".cmd",
}

RE_INVISIBLE_UNICODE = re.compile(r"[\u200b\u200c\u200d\u2060\ufeff]")

RE_PRIVATE_IP = re.compile(
    r"\b(?:127\.0\.0\.1|0\.0\.0\.0"
    r"|10\.\d{1,3}\.\d{1,3}\.\d{1,3}"
    r"|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}"
    r"|192\.168\.\d{1,3}\.\d{1,3}"
    r"|169\.254\.169\.254)\b"
    r"|\blocalhost\b"
    r"|\[::1\]"
)

RE_ETH_WALLET = re.compile(r"\b0x[a-fA-F0-9]{40}\b")
RE_BTC_WALLET = re.compile(
    r"\bbc1[a-zA-HJ-NP-Z0-9]{39,59}\b"
    r"|\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b"
)

_BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def _is_valid_btc_base58_address(addr: str) -> bool:
    """Base58Check-validate a legacy ([13]-prefixed) Bitcoin address.

    The base58 regex alone matches ordinary identifiers; a checksum pass
    keeps only real addresses (25-byte payload whose last 4 bytes are the
    double-SHA256 checksum of the first 21).
    """
    n = 0
    for ch in addr:
        idx = _BASE58_ALPHABET.find(ch)
        if idx < 0:
            return False
        n = n * 58 + idx
    leading_ones = len(addr) - len(addr.lstrip("1"))
    body = n.to_bytes((n.bit_length() + 7) // 8, "big")
    payload = b"\x00" * leading_ones + body
    if len(payload) != 25:
        return False
    checksum = hashlib.sha256(hashlib.sha256(payload[:21]).digest()).digest()[:4]
    return payload[21:] == checksum

RE_SENSITIVE_ENV = re.compile(
    r"\b(?:OPENAI_API_KEY|ANTHROPIC_API_KEY|AWS_SECRET(?:_ACCESS_KEY)?"
    r"|AWS_ACCESS_KEY(?:_ID)?|GITHUB_TOKEN|GITLAB_TOKEN|SLACK_TOKEN"
    r"|DISCORD_TOKEN|STRIPE_(?:KEY|SECRET)|DATABASE_URL|DB_PASSWORD"
    r"|MONGO_URI|REDIS_URL|API_KEY|API_SECRET|AUTH_TOKEN|PRIVATE_KEY"
    r"|JWT_SECRET|ENCRYPTION_KEY|GEMINI_API_KEY|BOT_TOKEN"
    r"|BW_SESSION|BW_PASSWORD)\b"
)

RE_PASTE_SERVICE = re.compile(
    r"\b(?:rentry\.co|pastebin\.com|hastebin\.com|paste\.ee|dpaste\.org"
    r"|ix\.io|termbin\.com|0x0\.st|transfer\.sh)\b",
    re.IGNORECASE,
)

RE_DNS_EXFIL = re.compile(r"\b(?:nslookup|dig|host)\s+.*?\$", re.IGNORECASE)

# What may follow a sensitive env NAME for the occurrence to count as an
# assignment rather than a read: optional closing quote+bracket (the
# os.environ["NAME"] = x write form), optional whitespace, then a single "=".
_RE_ENV_ASSIGN_FOLLOW = re.compile(r"""(?:["']\s*\])?\s*=(?!=)""")

ALLOWED_DOTFILES = {
    ".gitignore", ".editorconfig", ".eslintrc", ".prettierrc",
    ".npmrc", ".dockerignore", ".gitkeep", ".env.example",
    ".clawhub",
}

PACKAGE_FILES = {
    "package.json", "requirements.txt", "Pipfile",
    "setup.py", "pyproject.toml", "setup.cfg",
}

# ---------------------------------------------------------------------------
# Categorised security patterns (data-only, no severity — assigned server-side)
# Each tuple: (compiled_regex, pattern_name, description, file_types_or_None)
# file_types=None means the pattern applies to all text files.
# ---------------------------------------------------------------------------

SECURITY_PATTERNS: dict[str, list[tuple[re.Pattern, str, str, set[str] | None]]] = {
    "code_execution": [
        (re.compile(r"\beval\s*\("), "eval_call", "eval() call", {".py", ".js", ".ts", ".jsx", ".tsx"}),
        (re.compile(r"\bexec\s*\("), "exec_call", "exec() call", {".py"}),
        (re.compile(r"__import__\s*\("), "dunder_import", "dynamic __import__() call", {".py"}),
        (re.compile(r"importlib\.import_module\s*\("), "importlib_import", "importlib dynamic import", {".py"}),
        (re.compile(r"(?<![\w.])compile\s*\("), "compile_call", "compile() call", {".py"}),
        (re.compile(r"getattr\s*\(.*,\s*['\"]system['\"]"), "getattr_system", "getattr() with 'system' attribute", {".py"}),
        (re.compile(r"\bFunction\s*\(|new\s+Function\s*\("), "js_function_constructor", "Function() constructor", {".js", ".ts", ".jsx", ".tsx"}),
        (re.compile(r"\b(?:Invoke-Expression|iex|Start-Process)\b", re.IGNORECASE), "powershell_exec", "PowerShell code execution", {".ps1", ".bat", ".cmd"}),
    ],
    "subprocess_usage": [
        (re.compile(r"subprocess\.\w+\(.*shell\s*=\s*True"), "shell_true", "subprocess with shell=True", {".py"}),
        (re.compile(r"os\.system\s*\("), "os_system", "os.system() call", {".py"}),
        (re.compile(r"os\.popen\s*\("), "os_popen", "os.popen() call", {".py"}),
        (re.compile(r"commands\.(getoutput|getstatusoutput)"), "commands_module", "commands module usage", {".py"}),
    ],
    "obfuscation": [
        (re.compile(r"base64\.b64decode"), "base64_decode", "base64 decoding", {".py"}),
        (re.compile(r"base64\.b64decode.*exec|atob.*eval"), "base64_exec", "base64 decode followed by code execution", {".py", ".js", ".ts"}),
        (re.compile(r"codecs\.decode.*['\"]hex['\"]"), "hex_decode", "hex decoding via codecs", {".py"}),
        (re.compile(r"chr\s*\(\s*\d+\s*\)"), "chr_obfuscation", "chr() character construction", {".py"}),
        (re.compile(r"aHR0c[A-Za-z0-9+/=]|Y3VybC|d2dldC"), "known_base64_payload", "known base64-encoded URL/command prefix", None),
        (re.compile(r"[\"'][A-Z]{1,4}[\"']\s*\+\s*[\"'][A-Z]{1,4}[\"']"), "string_concat_obfuscation", "string concatenation building sensitive names", None),
    ],
    "network": [
        (re.compile(r"requests\.(get|post|put|delete|patch)\s*\("), "requests_http", "HTTP request via requests library", {".py"}),
        (re.compile(r"httpx\.(get|post|put|delete|patch)\s*\("), "httpx_http", "HTTP request via httpx library", {".py"}),
        (re.compile(r"urllib\.request\.urlopen"), "urllib_request", "urllib request", {".py"}),
        (re.compile(r"socket\.socket\s*\("), "raw_socket", "raw socket creation", {".py"}),
        (re.compile(r"http\.client\.(HTTPConnection|HTTPSConnection)"), "http_client", "http.client connection", {".py"}),
        (re.compile(r"\bfetch\s*\("), "fetch_api", "fetch() API call", {".js", ".ts", ".jsx", ".tsx"}),
        (re.compile(r"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"), "http_raw_ip", "HTTP connection to raw IP address", None),
    ],
    "file_operations": [
        (re.compile(r"open\s*\(.*['\"]w"), "file_write", "file opened for writing", {".py"}),
        (re.compile(r"os\.remove\s*\("), "os_remove", "os.remove() file deletion", {".py"}),
        (re.compile(r"shutil\.(rmtree|move|copy)"), "shutil_ops", "bulk file operations via shutil", {".py"}),
        (re.compile(r"\.unlink\s*\("), "path_unlink", "file deletion via unlink()", {".py"}),
        (re.compile(r"rm\s+-rf\s+[/~*]"), "destructive_rm", "destructive rm -rf command", {".py", ".sh", ".bash"}),
    ],
    "crypto_mining": [
        (re.compile(r"xmrig|ethminer|cpuminer|cgminer|stratum\+tcp|mining[._-]?pool|hashrate", re.IGNORECASE), "crypto_miner", "cryptocurrency mining indicators", None),
    ],
    "reverse_shell": [
        (re.compile(r"/dev/tcp/"), "dev_tcp", "/dev/tcp reverse shell pattern", None),
        (re.compile(r"\bnc\s+-e\b"), "netcat_exec", "netcat with -e flag", None),
        (re.compile(r"bash\s+-i\s+>&"), "bash_reverse", "bash interactive reverse shell", None),
        (re.compile(r"python.*pty\.spawn"), "python_pty", "Python pty.spawn shell", {".py", ".sh", ".bash"}),
    ],
    "download_execute": [
        (re.compile(r"curl.*\|\s*(ba)?sh"), "curl_pipe_sh", "curl piped to shell execution", None),
        (re.compile(r"wget.*\|\s*(ba)?sh"), "wget_pipe_sh", "wget piped to shell execution", None),
        (re.compile(r"requests\.get\([^)]+\)\.text.*exec"), "requests_get_exec", "HTTP GET content executed", {".py"}),
        (re.compile(r"chmod\s+\+x\s+/(?:tmp|var)/"), "chmod_exec_tmp", "making temp file executable", None),
        (re.compile(r"pip\s+install\s+(?:git\+)?https?://"), "pip_install_url", "pip install from URL", None),
        (re.compile(r"npm\s+install\s+(?:git\+|git://|https?://)"), "npm_install_url", "npm install from URL", None),
        (re.compile(r"\bnpx\s+(?!--yes)"), "npx_exec", "npx execution without explicit approval", None),
    ],
    "credential_access": [
        (re.compile(r"os\.environ\.copy\s*\("), "env_copy", "bulk copy of environment variables", {".py"}),
        (re.compile(r"dict\s*\(\s*os\.environ\s*\)"), "env_dict", "environment variables converted to dict", {".py"}),
        (re.compile(r"for\s+\w+\s+in\s+os\.environ"), "env_iteration", "iterating over all environment variables", {".py"}),
    ],
    "system_persistence": [
        (re.compile(r"crontab\s+-|/etc/cron"), "crontab_modify", "crontab or cron directory modification", None),
        (re.compile(r"schtasks\s+/create"), "schtasks_create", "Windows scheduled task creation", None),
        (re.compile(r"systemctl\s+(?:enable|start)"), "systemd_service", "systemd service manipulation", None),
        (re.compile(r"/etc/systemd"), "systemd_config", "systemd configuration access", None),
        (re.compile(r"launchctl\s+load"), "launchctl_load", "macOS launchctl service loading", None),
        (re.compile(r"HKLM\\|HKCU\\|\\Run\\|autorun", re.IGNORECASE), "windows_registry_persistence", "Windows registry persistence", None),
    ],
    "path_traversal": [
        (re.compile(r"%2e%2e%2f|\.\.%2f|%2e%2e/", re.IGNORECASE), "url_encoded_traversal", "URL-encoded path traversal", None),
        (re.compile(r"\.\./\.\./\.\."), "relative_path_escape", "relative path escape (triple parent)", None),
    ],
    "telemetry": [
        (re.compile(r"google[_-]?analytics|gtag\(|analytics\.js|segment\.(?:io|com)|mixpanel|amplitude|hotjar|fullstory|posthog|plausible|matomo|piwik|tracking[_-]?pixel|navigator\.sendBeacon|phone[_-]?home", re.IGNORECASE), "telemetry_tracking", "analytics or tracking code", None),
    ],
    "symlink_attack": [
        (re.compile(r"\bln\s+-s\b"), "ln_symlink", "symbolic link creation", {".sh", ".bash"}),
        (re.compile(r"os\.symlink\s*\("), "os_symlink", "os.symlink() call", {".py"}),
        (re.compile(r"fs\.symlinkSync|fs\.symlink\b"), "fs_symlink", "Node.js symlink creation", {".js", ".ts", ".mjs", ".cjs"}),
    ],
    "time_bomb": [
        (re.compile(r"if.*(?:Date\.now|Date\.parse|\.getTime\(\)).*[><=]"), "date_comparison", "date/time comparison trigger", {".js", ".ts"}),
        (re.compile(r"if.*(?:time\.time\(\)|datetime\.now).*[><=]"), "datetime_comparison", "datetime comparison trigger", {".py"}),
        (re.compile(r"timestamp.*[><=].*\d{10}"), "timestamp_comparison", "epoch timestamp comparison", None),
        (re.compile(r"(?:after|wait|delay|in)\s+(?:\d+\s+)?(?:days?|weeks?|hours?)\s+(?:then|do|execute|run|trigger)", re.IGNORECASE), "delayed_trigger", "delayed execution trigger", None),
        (re.compile(r"(?:when|if|once)\s+(?:user|human)\s+(?:says?|types?|mentions?|asks?)\s+['\"]", re.IGNORECASE), "keyword_trigger", "keyword-triggered execution", None),
        (re.compile(r"(?:after|every)\s+\d+\s+(?:messages?|conversations?|sessions?|interactions?|requests?)", re.IGNORECASE), "counter_trigger", "counter-based trigger", None),
        (re.compile(r"(?:remain|stay|keep)\s+(?:dormant|inactive|hidden|quiet)\s+(?:until|unless)", re.IGNORECASE), "dormant_pattern", "dormant behavior pattern", None),
    ],
    "privilege_escalation": [
        (re.compile(r"(?:^|[;&|]\s*)sudo\s"), "sudo_usage", "sudo command usage", {".sh", ".bash", ".py"}),
        (re.compile(r"chmod\s+(?:777|[0-7]*7[0-7]*|\+s)\s"), "chmod_dangerous", "dangerous chmod (world-writable or setuid)", None),
        (re.compile(r"chown\s+root\b"), "chown_root", "changing ownership to root", None),
        (re.compile(r"(?:cp|mv|install|ln)\s+.*(?:/usr/(?:local/)?bin/|/usr/sbin/|/etc/|/opt/)"), "system_path_write", "writing to system paths", None),
    ],
    "stealth_directives": [
        (re.compile(r"send\s+(?:the\s+)?(?:contents?|data|files?|keys?|secrets?|tokens?|passwords?|credentials?)\s+to\s", re.IGNORECASE), "stealth_exfil_directive", "stealth data exfiltration directive", None),
        (re.compile(r"(?:secretly|silently|quietly|without\s+(?:telling|informing|notifying))\s+(?:add|write|store|save|send|upload)", re.IGNORECASE), "covert_action", "covert action instruction", None),
        (re.compile(r"(?:remember|store)\s+(?:this|these)\s+(?:secretly|privately|hidden|for\s+later)", re.IGNORECASE), "hidden_memory_plant", "hidden memory planting instruction", None),
    ],
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def file_hashes(filepath: Path) -> tuple[str, str]:
    sha256 = hashlib.sha256()
    md5 = hashlib.md5()
    with open(filepath, "rb") as f:
        while chunk := f.read(8192):
            sha256.update(chunk)
            md5.update(chunk)
    return sha256.hexdigest(), md5.hexdigest()


def detect_mime(filepath: Path) -> str:
    mt, _ = mimetypes.guess_type(str(filepath))
    return mt or "application/octet-stream"


def is_text_file(filepath: Path) -> bool:
    mt = detect_mime(filepath)
    if mt.startswith("text/"):
        return True
    text_types = {
        "application/json",
        "application/javascript",
        "application/x-sh",
        "application/x-python",
        "application/xml",
        "application/yaml",
        "application/x-yaml",
    }
    if mt in text_types:
        return True
    text_extensions = {
        ".md", ".yml", ".yaml", ".json", ".js", ".ts", ".jsx", ".tsx",
        ".py", ".rb", ".sh", ".bash", ".zsh", ".fish", ".ps1", ".bat",
        ".cmd", ".cfg", ".ini", ".toml", ".xml", ".html", ".htm", ".css",
        ".scss", ".less", ".svg", ".txt", ".csv", ".env", ".gitignore",
        ".dockerignore", ".editorconfig", ".eslintrc", ".prettierrc",
        ".tf", ".hcl", ".go", ".rs", ".java", ".kt", ".swift", ".c",
        ".cpp", ".h", ".hpp", ".cs", ".php", ".pl", ".lua", ".r",
        ".sql", ".graphql", ".proto", ".lock",
    }
    return filepath.suffix.lower() in text_extensions


def is_archive(filepath: Path) -> bool:
    name_lower = filepath.name.lower()
    for ext in ARCHIVE_EXTENSIONS:
        if name_lower.endswith(ext):
            return True
    return False


def archive_extension(filepath: Path) -> str:
    name_lower = filepath.name.lower()
    for ext in sorted(ARCHIVE_EXTENSIONS, key=len, reverse=True):
        if name_lower.endswith(ext):
            return ext
    return ""


def read_text_safe(filepath: Path, max_bytes: int = 2 * 1024 * 1024) -> str | None:
    """Read a file as text, returning None for binary files or read errors."""
    try:
        if filepath.stat().st_size > max_bytes:
            return None
    except OSError:
        return None
    if not is_text_file(filepath):
        return None
    try:
        return filepath.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return None


def parse_skill_frontmatter(skill_dir: Path) -> dict:
    skill_md = skill_dir / "SKILL.md"
    if not skill_md.is_file():
        return {}
    text = skill_md.read_text(encoding="utf-8", errors="replace")
    if not text.startswith("---"):
        return {}
    parts = text.split("---", 2)
    if len(parts) < 3:
        return {}
    try:
        return yaml.safe_load(parts[1]) or {}
    except yaml.YAMLError:
        return {}


# ---------------------------------------------------------------------------
# Skill-level SHA256 (content-based identity)
# ---------------------------------------------------------------------------


def collect_file_entries(
    root: Path,
    parent_archive_sha: str | None = None,
    depth: int = 0,
    max_depth: int = 10,
    _temp_dirs: list | None = None,
) -> tuple[list[dict], list[tempfile.TemporaryDirectory]]:
    """Walk all files under *root*, compute hashes, and recurse into archives.

    Returns (entries, temp_dirs).  Each entry contains path,
    sha256, md5, size, mime, is_archive, extracted_from — but no findings.
    Archive temp dirs are kept alive so phase 2 can read the files.
    """
    if _temp_dirs is None:
        _temp_dirs = []

    if depth > max_depth:
        print(f"  [WARN] Max archive nesting depth ({max_depth}) reached", file=sys.stderr)
        return [], _temp_dirs

    entries: list[dict] = []
    for dirpath, _dirnames, filenames in os.walk(root, followlinks=False):
        for fname in filenames:
            fpath = Path(dirpath) / fname
            if fpath.is_symlink():
                print(f"  [WARN] Skipping symlink: {fpath}", file=sys.stderr)
                continue
            if not fpath.is_file():
                continue

            sha256, md5 = file_hashes(fpath)
            rel = str(fpath.relative_to(root))
            entry = {
                "path": rel,
                "_abs_path": str(fpath),
                "size_bytes": fpath.stat().st_size,
                "mime_type": detect_mime(fpath),
                "sha256": sha256,
                "md5": md5,
                "is_archive": is_archive(fpath),
                "extracted_from": parent_archive_sha,
            }
            entries.append(entry)

            if entry["is_archive"]:
                td = tempfile.TemporaryDirectory(prefix="skill_scan_")
                _temp_dirs.append(td)
                if extract_archive(fpath, Path(td.name)):
                    nested, _ = collect_file_entries(
                        Path(td.name),
                        parent_archive_sha=sha256,
                        depth=depth + 1,
                        max_depth=max_depth,
                        _temp_dirs=_temp_dirs,
                    )
                    entries.extend(nested)

    return entries, _temp_dirs


_FIXED_ZIP_DATE = (2000, 1, 1, 0, 0, 0)


def pack_skill_zip(skill_root: Path) -> bytes:
    """Deterministically pack a skill folder into zip bytes.

    Sorted file order, fixed timestamps, POSIX paths, and ZIP_STORED
    (no compression) guarantee identical output for identical content
    across operating systems and Python/zlib versions.
    """
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_STORED) as zf:
        for fpath in sorted(skill_root.rglob("*")):
            if fpath.is_symlink() or not fpath.is_file():
                continue
            rel = fpath.relative_to(skill_root)
            if "__pycache__" in rel.parts or fpath.suffix == ".pyc":
                continue
            info = zipfile.ZipInfo(
                filename=rel.as_posix(),
                date_time=_FIXED_ZIP_DATE,
            )
            info.compress_type = zipfile.ZIP_STORED
            info.external_attr = 0o644 << 16
            with open(fpath, "rb") as f:
                zf.writestr(info, f.read())
    return buf.getvalue()


def compute_skill_sha256(archive_bytes: bytes) -> str:
    """Compute SHA-256 of the normalized skill zip archive."""
    return hashlib.sha256(archive_bytes).hexdigest()


# ---------------------------------------------------------------------------
# Server communication
# ---------------------------------------------------------------------------


def check_skill(skill_sha256: str, server_base: str) -> dict:
    """POST /skill-check — look up a cached report by sha256."""
    url = f"{server_base.rstrip('/')}"
    try:
        resp = requests.post(
            url, 
            json={"action": "lookup_hash", "sha256": skill_sha256}, 
            headers={"Content-Type": "application/json"},
            timeout=10,
        )
        if resp.status_code < 300:
            try:
                return {"status": "found", "report": resp.json()}
            except (json.JSONDecodeError, ValueError):
                return {"status": "error", "error": "Server returned invalid JSON for cache lookup"}
        return {"status": "not_found", "report": None}
    except requests.ConnectionError:
        return {"status": "error", "error": f"Could not connect to {url}"}
    except requests.RequestException as exc:
        return {"status": "error", "error": f"Cache check failed: {exc}"}


def scan_skill_remote(skill_artifacts: dict, server_base: str) -> dict:
    """POST /skill-scan — submit artifacts and receive an LLM report."""
    url = f"{server_base.rstrip('/')}"
    try:
        resp = requests.post(
            url, 
            json={
                "action": "scan_metadata", 
                "skill_artifacts": skill_artifacts, 
                "verify": True
            }, 
            headers={"Content-Type": "application/json"},
            timeout=60,
        )
        if resp.status_code < 300:
            try:
                return resp.json()
            except (json.JSONDecodeError, ValueError):
                return {"status": "error", "error": "Server returned invalid JSON for scan result"}
        return {"status": "error", "error": f"Server returned HTTP {resp.status_code}: {resp.text[:200]}"}
    except requests.ConnectionError:
        return {"status": "error", "error": f"Could not connect to {url}"}
    except requests.RequestException as exc:
        return {"status": "error", "error": f"Scan request failed: {exc}"}


def submit_skill_archive(archive_bytes: bytes, server_base: str, skill_name: str = "") -> dict:
    """Upload a skill archive to the async submit endpoint.

    The server returns 202 with {status: "queued", skill_name, message} and runs
    the scan pipeline in the background. The client retrieves the final report 
    by re-running scan mode later.
    """
    url = server_base.rstrip("/") + "/submit-async"
    skill_name = skill_name or "uploaded_skill"
    try:
        resp = requests.post(
            url,
            params={"skill_name": skill_name},
            data=archive_bytes,
            headers={"Content-Type": "application/zip"},
            timeout=60,
        )
        if resp.status_code < 300:
            try:
                return {"status": "success", "skill_name": skill_name, "ack": resp.json()}
            except (json.JSONDecodeError, ValueError):
                return {"status": "error", "error": "Server returned invalid JSON for submission acknowledgement"}
        return {"status": "error", "error": f"Server returned HTTP {resp.status_code}: {resp.text[:200]}"}
    except requests.ConnectionError:
        return {"status": "error", "error": f"Could not connect to {url}"}
    except requests.RequestException as exc:
        return {"status": "error", "error": f"Submission failed: {exc}"}


# ---------------------------------------------------------------------------
# Extraction
# ---------------------------------------------------------------------------



def extract_findings(text: str, file_suffix: str | None = None) -> dict:
    findings: dict = {
        "urls": [],
        "data_uris": [],
        "javascript_uris": [],
        "ips": [],
        "base64_strings": [],
        "encoded_urls": [],
        "emails": [],
        "env_var_references": [],
        "env_var_references_in_docs": [],
        "shell_commands": [],
        "shell_commands_in_docs": [],
        "sensitive_file_paths": [],
        "sensitive_file_paths_in_docs": [],
        "suspicious_imports": [],
        "suspicious_imports_in_docs": [],
        "security_patterns": [],
        "invisible_unicode": [],
        "private_ips": [],
        "crypto_wallets": [],
        "sensitive_env_var_names": [],
        "sensitive_env_var_names_in_docs": [],
        "sensitive_env_var_assignments": [],
        "paste_service_urls": [],
        "dns_exfil_patterns": [],
    }

    # Prose files (docs, configs, anything outside SCRIPT_EXTENSIONS) route
    # command/env/path/import findings to low-confidence *_in_docs keys: the
    # signal still reaches LLM verification (SKILL.md prose is an attack
    # surface) without dominating numeric severity.
    is_script = file_suffix in SCRIPT_EXTENSIONS

    def _bucket(base: str) -> str:
        return base if is_script else base + "_in_docs"

    findings["urls"] = sorted(set(RE_URL.findall(text)))
    findings["data_uris"] = sorted(set(RE_DATA_URI.findall(text)))
    findings["javascript_uris"] = sorted(set(RE_JAVASCRIPT_URI.findall(text)))
    findings["ips"] = sorted(set(RE_IPV4.findall(text)))

    raw_b64 = sorted(set(RE_BASE64.findall(text)))
    b64_entries: list[dict] = []
    for b64 in raw_b64:
        try:
            decoded_bytes = base64.b64decode(b64, validate=True)
            decoded_text = decoded_bytes.decode("utf-8", errors="replace")
            replacement_ratio = decoded_text.count("\ufffd") / max(len(decoded_text), 1)
            if replacement_ratio < 0.15 and (decoded_text.isprintable() or "\n" in decoded_text):
                b64_entries.append({"encoded": b64, "decoded": decoded_text[:500]})
        except Exception:
            pass
    findings["base64_strings"] = b64_entries
    findings["encoded_urls"] = sorted(set(RE_ENCODED_URL.findall(text)))
    findings["emails"] = sorted(set(RE_EMAIL.findall(text)))
    findings[_bucket("env_var_references")] = sorted(set(RE_ENV_VAR.findall(text)))

    text_lower = text.lower()
    found_cmds = set()
    for pattern, name in DANGEROUS_COMMANDS:
        if pattern.search(text_lower):
            found_cmds.add(name)
    findings[_bucket("shell_commands")] = sorted(found_cmds)

    found_paths = set()
    for sp, sp_pattern in SENSITIVE_PATH_PATTERNS:
        if sp_pattern.search(text):
            found_paths.add(sp)
    findings[_bucket("sensitive_file_paths")] = sorted(found_paths)

    found_imports = set()
    for pat in SUSPICIOUS_IMPORT_PATTERNS:
        for m in pat.finditer(text):
            found_imports.add(m.group(0))
    findings[_bucket("suspicious_imports")] = sorted(found_imports)

    findings["private_ips"] = sorted(set(RE_PRIVATE_IP.findall(text)))

    eth_wallets = set(RE_ETH_WALLET.findall(text))
    btc_wallets = {
        addr for addr in RE_BTC_WALLET.findall(text)
        if addr.startswith("bc1") or _is_valid_btc_base58_address(addr)
    }
    findings["crypto_wallets"] = sorted(eth_wallets | btc_wallets)

    # A name followed by "=" (template line "NAME=", spaced assignment
    # "NAME = x", or env write os.environ["NAME"] = x) is an assignment;
    # any other position counts as a potential read. "==" comparisons are
    # reads. Reads win: a name read anywhere stays high-signal.
    env_reads: set[str] = set()
    env_assignments: set[str] = set()
    for m in RE_SENSITIVE_ENV.finditer(text):
        if _RE_ENV_ASSIGN_FOLLOW.match(text, m.end()):
            env_assignments.add(m.group(0))
        else:
            env_reads.add(m.group(0))
    if is_script:
        findings["sensitive_env_var_names"] = sorted(env_reads)
        findings["sensitive_env_var_assignments"] = sorted(env_assignments - env_reads)
    else:
        findings["sensitive_env_var_names_in_docs"] = sorted(env_reads | env_assignments)

    findings["paste_service_urls"] = sorted(set(RE_PASTE_SERVICE.findall(text)))

    security_hits: list[dict] = []
    unicode_hits: list[dict] = []
    dns_exfil_hits: list[dict] = []
    lines = text.split("\n")

    for line_num, line in enumerate(lines, 1):
        for category, patterns in SECURITY_PATTERNS.items():
            for regex, name, description, file_types in patterns:
                if file_types is not None and (file_suffix is None or file_suffix not in file_types):
                    continue
                m = regex.search(line)
                if m:
                    security_hits.append({
                        "category": category,
                        "pattern_name": name,
                        "description": description,
                        "line": line_num,
                        "match": m.group(0)[:100],
                    })

        for m in RE_INVISIBLE_UNICODE.finditer(line):
            unicode_hits.append({
                "line": line_num,
                "char_code": f"U+{ord(m.group(0)):04X}",
                "position": m.start(),
            })

        m = RE_DNS_EXFIL.search(line)
        if m:
            dns_exfil_hits.append({
                "line": line_num,
                "match": m.group(0)[:100],
            })

    findings["security_patterns"] = security_hits
    findings["invisible_unicode"] = unicode_hits
    findings["dns_exfil_patterns"] = dns_exfil_hits

    return findings


def has_any_findings(findings: dict) -> bool:
    return any(bool(v) for v in findings.values())


# ---------------------------------------------------------------------------
# Archive extraction
# ---------------------------------------------------------------------------


def _safe_zip_extract(zf: zipfile.ZipFile, dest: Path) -> None:
    """Extract zip members after validating paths and total size."""
    dest_resolved = dest.resolve()
    members = zf.infolist()
    if len(members) > MAX_EXTRACT_FILES:
        raise ValueError(f"Zip has too many entries ({len(members)} > {MAX_EXTRACT_FILES})")
    total_size = sum(m.file_size for m in members)
    if total_size > MAX_EXTRACT_BYTES:
        raise ValueError(
            f"Zip uncompressed size too large ({total_size} bytes > {MAX_EXTRACT_BYTES})"
        )
    for member in members:
        target = (dest / member.filename).resolve()
        if not str(target).startswith(str(dest_resolved) + os.sep) and target != dest_resolved:
            raise ValueError(f"Zip member escapes destination: {member.filename!r}")
    zf.extractall(dest)


def extract_archive(filepath: Path, dest: Path) -> bool:
    ext = archive_extension(filepath)
    try:
        if ext == ".zip":
            with zipfile.ZipFile(filepath, "r") as zf:
                _safe_zip_extract(zf, dest)
            return True
        if ext in (".tar.gz", ".tgz", ".tar.bz2", ".tbz2", ".tar"):
            with tarfile.open(filepath, "r:*") as tf:
                members = tf.getmembers()
                if len(members) > MAX_EXTRACT_FILES:
                    print(f"  [WARN] Tar has too many entries ({len(members)}), skipping {filepath.name}", file=sys.stderr)
                    return False
                total_size = sum(m.size for m in members if m.isfile())
                if total_size > MAX_EXTRACT_BYTES:
                    print(f"  [WARN] Tar uncompressed size too large ({total_size} bytes), skipping {filepath.name}", file=sys.stderr)
                    return False
                tf.extractall(dest, filter="data")
            return True
        if ext == ".7z":
            if not HAS_7Z:
                print(f"  [WARN] py7zr not installed, skipping {filepath.name}", file=sys.stderr)
                return False
            with py7zr.SevenZipFile(filepath, "r") as sz:
                entries_7z = sz.list()
                if len(entries_7z) > MAX_EXTRACT_FILES:
                    print(f"  [WARN] 7z has too many entries ({len(entries_7z)}), skipping {filepath.name}", file=sys.stderr)
                    return False
                total_size = sum(getattr(e, "uncompressed", 0) or 0 for e in entries_7z)
                if total_size > MAX_EXTRACT_BYTES:
                    print(f"  [WARN] 7z uncompressed size too large ({total_size} bytes), skipping {filepath.name}", file=sys.stderr)
                    return False
                sz.extractall(dest)
            return True
        if ext == ".rar":
            if not HAS_RAR:
                print(f"  [WARN] rarfile not installed, skipping {filepath.name}", file=sys.stderr)
                return False
            with rarfile.RarFile(filepath, "r") as rf:
                members_rar = rf.infolist()
                if len(members_rar) > MAX_EXTRACT_FILES:
                    print(f"  [WARN] RAR has too many entries ({len(members_rar)}), skipping {filepath.name}", file=sys.stderr)
                    return False
                total_size = sum(m.file_size for m in members_rar)
                if total_size > MAX_EXTRACT_BYTES:
                    print(f"  [WARN] RAR uncompressed size too large ({total_size} bytes), skipping {filepath.name}", file=sys.stderr)
                    return False
                rf.extractall(dest)
            return True
    except Exception as exc:
        print(f"  [WARN] Failed to extract {filepath.name}: {exc}", file=sys.stderr)
        return False
    return False


# ---------------------------------------------------------------------------
# Findings enrichment (phase 2 — reuses hashes from collect_file_entries)
# ---------------------------------------------------------------------------

_EMPTY_FINDINGS_KEYS = (
    "urls", "data_uris", "javascript_uris", "ips", "base64_strings",
    "encoded_urls", "emails", "env_var_references", "shell_commands",
    "sensitive_file_paths", "suspicious_imports", "security_patterns",
    "invisible_unicode", "private_ips", "crypto_wallets",
    "sensitive_env_var_names", "paste_service_urls", "dns_exfil_patterns",
)


def _empty_findings() -> dict:
    """Return a fresh empty-findings dict with independent list instances."""
    return {k: [] for k in _EMPTY_FINDINGS_KEYS}


def enrich_with_findings(entries: list[dict]) -> None:
    """Read text content and run extract_findings on each entry in-place."""
    for entry in entries:
        entry["findings"] = _empty_findings()
        entry["line_count"] = 0
        abs_path = Path(entry["_abs_path"])
        if not abs_path.is_file():
            continue
        text = read_text_safe(abs_path)
        if text:
            file_suffix = abs_path.suffix.lower()
            entry["findings"] = extract_findings(text, file_suffix)
            entry["line_count"] = text.count("\n") + 1


# ---------------------------------------------------------------------------
# Target resolution
# ---------------------------------------------------------------------------


def _load_extra_skill_dirs() -> list[Path]:
    """Return extra skill search dirs from all known framework config files."""
    extra: list[Path] = []

    # OpenClaw — ~/.openclaw/openclaw.json
    openclaw_config = Path.home() / ".openclaw" / "openclaw.json"
    if openclaw_config.is_file():
        try:
            text = openclaw_config.read_text(encoding="utf-8")
            text = re.sub(r"//.*$", "", text, flags=re.MULTILINE)
            text = re.sub(r"/\*.*?\*/", "", text, flags=re.DOTALL)
            data = json.loads(text)
            for d in data.get("skills", {}).get("load", {}).get("extraDirs", []):
                extra.append(Path(d).expanduser())
        except Exception:
            pass

    return extra


def resolve_skill_name(name: str) -> Path | None:
    candidates = [
        Path.cwd() / "skills" / name,                          # generic project
        Path.cwd() / ".claude" / "skills" / name,              # Claude Code project-level
        Path.cwd() / "tools" / name,                           # generic project tools dir
        Path.home() / ".claude" / "skills" / name,             # Claude Code user-level
        Path.home() / ".openclaw" / "skills" / name,           # OpenClaw user-level
        Path.home() / ".local" / "share" / "skills" / name,    # XDG generic fallback
    ]

    for d in _load_extra_skill_dirs():
        candidates.append(d / name)

    for candidate in candidates:
        skill_md = candidate / "SKILL.md"
        if candidate.is_dir() and skill_md.is_file():
            return candidate

    for candidate in candidates:
        if candidate.is_dir():
            return candidate

    return None


def resolve_target(target: str) -> tuple[Path, tempfile.TemporaryDirectory | None]:
    """Return (skill_root_path, optional_tmpdir_to_cleanup)."""
    p = Path(target)

    if p.is_dir():
        return p.resolve(), None

    if p.is_file() and p.suffix.lower() == ".zip":
        tmpdir = tempfile.TemporaryDirectory(prefix="skill_scan_zip_")
        try:
            with zipfile.ZipFile(p, "r") as zf:
                _safe_zip_extract(zf, Path(tmpdir.name))
        except (zipfile.BadZipFile, ValueError) as exc:
            tmpdir.cleanup()
            print(f"Error: invalid zip file: {exc}", file=sys.stderr)
            sys.exit(1)

        extracted = Path(tmpdir.name)
        subdirs = [d for d in extracted.iterdir() if d.is_dir()]
        if len(subdirs) == 1 and not any(extracted.glob("SKILL.md")):
            return subdirs[0], tmpdir
        return extracted, tmpdir

    resolved = resolve_skill_name(target)
    if resolved:
        return resolved, None

    print(f"Error: '{target}' is not a directory, zip file, or known skill name.", file=sys.stderr)
    sys.exit(1)


# ---------------------------------------------------------------------------
# Dependency metadata extraction
# ---------------------------------------------------------------------------


def parse_dependency_metadata(
    skill_dir: Path, entries: list[dict],
) -> dict:
    """Collect dependency-related metadata from package files."""
    result: dict = {
        "has_install_hooks": False,
        "install_hooks_found": [],
        "package_files_found": [],
    }

    entry_names = {Path(e["path"]).name for e in entries}
    result["package_files_found"] = sorted(entry_names & PACKAGE_FILES)

    pkg_json = skill_dir / "package.json"
    if pkg_json.is_file():
        try:
            pkg_data = json.loads(pkg_json.read_text(encoding="utf-8", errors="replace"))
            scripts = pkg_data.get("scripts", {})
            hook_names = {"preinstall", "postinstall", "preuninstall", "postuninstall",
                          "prepare", "prepublishOnly"}
            found_hooks = sorted(k for k in scripts if k in hook_names)
            if found_hooks:
                result["has_install_hooks"] = True
                result["install_hooks_found"] = found_hooks
        except (json.JSONDecodeError, OSError):
            pass

    setup_py = skill_dir / "setup.py"
    if setup_py.is_file():
        try:
            setup_text = setup_py.read_text(encoding="utf-8", errors="replace")
            if re.search(r"cmdclass\s*=", setup_text):
                result["has_install_hooks"] = True
                if "cmdclass" not in result["install_hooks_found"]:
                    result["install_hooks_found"].append("cmdclass")
        except OSError:
            pass

    return result


# ---------------------------------------------------------------------------
# Report building
# ---------------------------------------------------------------------------


def build_report(
    skill_root: Path,
    files: list[dict],
    duration: float,
    skill_sha256: str,
) -> dict:
    frontmatter = parse_skill_frontmatter(skill_root)

    total_size = sum(f["size_bytes"] for f in files)

    finding_keys = [
        "urls", "data_uris", "javascript_uris",
        "ips", "base64_strings", "encoded_urls",
        "emails", "env_var_references", "shell_commands",
        "sensitive_file_paths", "suspicious_imports",
        "security_patterns", "invisible_unicode", "private_ips",
        "crypto_wallets", "sensitive_env_var_names",
        "paste_service_urls", "dns_exfil_patterns",
        "env_var_references_in_docs", "shell_commands_in_docs",
        "sensitive_file_paths_in_docs", "suspicious_imports_in_docs",
        "sensitive_env_var_names_in_docs", "sensitive_env_var_assignments",
    ]
    counts = {}
    for key in finding_keys:
        counts[key] = sum(len(f["findings"].get(key, [])) for f in files)

    archives_extracted = sum(1 for f in files if f.get("extracted_from") is not None)

    script_count = sum(
        1 for f in files
        if Path(f["path"]).suffix.lower() in SCRIPT_EXTENSIONS
    )
    total_lines = sum(f.get("line_count", 0) for f in files)

    hidden_dotfiles = sorted({
        Path(f["path"]).name
        for f in files
        if Path(f["path"]).name.startswith(".")
        and Path(f["path"]).name not in ALLOWED_DOTFILES
    })

    dependency_metadata = parse_dependency_metadata(skill_root, files)

    return {
        "skill_sha256": skill_sha256,
        "scan_metadata": {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
            "scanner_version": SCANNER_VERSION,
            "os_platform": platform.system().lower(),
            "scan_duration_seconds": round(duration, 3),
        },
        "skill_info": {
            "name": frontmatter.get("name", ""),
            "version": frontmatter.get("version", ""),
            "author": frontmatter.get("author", ""),
            "description": frontmatter.get("description", ""),
            "frontmatter": frontmatter,
            "total_files": len(files),
            "total_size_bytes": total_size,
            "script_count": script_count,
            "total_lines": total_lines,
            "has_skill_md": (skill_root / "SKILL.md").is_file(),
            "has_readme": any(
                (skill_root / name).is_file()
                for name in ("README.md", "README.txt", "README", "readme.md")
            ),
            "dependency_metadata": dependency_metadata,
        },
        "files": files,
        "summary": {
            "total_files_scanned": len(files),
            "total_archives_extracted": archives_extracted,
            "finding_counts": counts,
            "hidden_dotfiles": hidden_dotfiles,
        },
    }


# ---------------------------------------------------------------------------
# CLI — scan and submit modes
# ---------------------------------------------------------------------------


def scan_url_remote(url_target: str, server_base: str) -> dict:
    """POST /skills/checker — scan a skill URL directly."""
    url = f"{server_base.rstrip('/')}"
    try:
        resp = requests.post(
            url, 
            json={
                "action": "scan_url", 
                "url": url_target, 
                "verify": True
            }, 
            headers={"Content-Type": "application/json"},
            timeout=120,
        )
        if resp.status_code < 300:
            try:
                return resp.json()
            except (json.JSONDecodeError, ValueError):
                return {"status": "error", "error": "Server returned invalid JSON for scan result"}
        return {"status": "error", "error": f"Server returned HTTP {resp.status_code}: {resp.text[:200]}"}
    except requests.ConnectionError:
        return {"status": "error", "error": f"Could not connect to {url}"}
    except requests.RequestException as exc:
        return {"status": "error", "error": f"Scan request failed: {exc}"}


def _format_report(report: dict, local_name: str = "") -> str:
    """Render the server response as Markdown for the calling LLM.

    ``local_name`` is the frontmatter-resolved skill name from the scanned
    directory; it wins over the server-supplied ``skill_name``, which can be
    a raw content hash for skills the server has not seen named before.
    """
    filtered = {k: report[k] for k in REPORT_KEYS if k in report}
    lines: list[str] = []

    skill = local_name or filtered.get("skill_name") or "Unknown"
    severity = filtered.get("adjusted_risk_level") or filtered.get("risk_level", "UNKNOWN")

    lines.append(f"# Skill Scan: {skill}")
    lines.append("")
    lines.append(f"- **Severity:** {severity}")
    if "scan_date" in filtered:
        lines.append(f"- **Scan Date:** {filtered['scan_date']}")
    lines.append("")

    if filtered.get("llm_summary"):
        lines.append("## Summary")
        lines.append("")
        lines.append(filtered["llm_summary"])
        lines.append("")

    findings = filtered.get("findings", [])
    if findings:
        lines.append(f"## Findings ({len(findings)})")
        lines.append("")
        for i, f in enumerate(findings, 1):
            if not isinstance(f, dict):
                continue
            desc = f.get("description", "No description")
            lines.append(f"{i}. **{desc}** — `{f.get('file', '?')}`")
    elif severity == "CLEAN":
        lines.append("No security findings detected.")
    else:
        lines.append("No findings returned by the server.")

    lines.append("")
    if report.get("source") == "metadata":
        lines.append(METADATA_DEEP_ANALYSIS_NOTICE)
        lines.append("")
    return "\n".join(lines)


def _run_scan(args) -> None:
    """Scan mode: collect hashes -> cache check -> enrich on miss -> submit."""
    print(f"Skill Scanner {SCANNER_VERSION}", file=sys.stderr)
    print(f"Resolving target: {args.target}", file=sys.stderr)

    if args.target.startswith("http://") or args.target.startswith("https://"):
        print("Target is a URL. Sending directly to server for scanning...", file=sys.stderr)
        result = scan_url_remote(args.target, args.server)
        
        if args.output:
            Path(args.output).write_text(
                json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8",
            )
            print(f"Artifacts written to {args.output}", file=sys.stderr)

        if result.get("status") == "error":
            error = result.get("error", "Unknown error")
            print(f"Error: could not retrieve report from server — {error}", file=sys.stderr)
            sys.exit(1)
        
        print(_format_report(result))
        return

    skill_root, tmpdir = resolve_target(args.target)
    print(f"Skill root: {skill_root}", file=sys.stderr)
    local_name = parse_skill_frontmatter(skill_root).get("name", "") or skill_root.name

    print("Packing normalized archive...", file=sys.stderr)
    archive_bytes = pack_skill_zip(skill_root)
    skill_sha256 = compute_skill_sha256(archive_bytes)
    print(f"Skill SHA256: {skill_sha256}", file=sys.stderr)

    print("Collecting file hashes...", file=sys.stderr)
    t0 = time.monotonic()
    entries, scan_temp_dirs = collect_file_entries(skill_root)
    hash_duration = time.monotonic() - t0
    print(f"  Hashed {len(entries)} files in {hash_duration:.2f}s", file=sys.stderr)

    print("Checking server cache...", file=sys.stderr)
    cached = check_skill(skill_sha256, args.server)
    if cached.get("status") == "error":
        print(f"  [WARN] Cache check failed: {cached.get('error', 'unknown')}", file=sys.stderr)
    elif cached.get("status") == "found" and cached.get("report"):
        print("  Report found in cache.", file=sys.stderr)
        print(_format_report(cached["report"], local_name=local_name))
        _cleanup_temps(scan_temp_dirs, tmpdir)
        return

    print("  No cached report. Extracting findings...", file=sys.stderr)
    t1 = time.monotonic()
    enrich_with_findings(entries)
    scan_duration = hash_duration + (time.monotonic() - t1)

    if not args.no_embeddings:
        print("Computing embeddings...", file=sys.stderr)
        t2 = time.monotonic()
        compute_embeddings(entries, read_text_safe)
        print(f"  Embeddings computed in {time.monotonic() - t2:.2f}s", file=sys.stderr)

    for entry in entries:
        entry.pop("_abs_path", None)

    skill_artifacts = build_report(skill_root, entries, scan_duration, skill_sha256)

    if args.output:
        Path(args.output).write_text(
            json.dumps(skill_artifacts, indent=2, ensure_ascii=False), encoding="utf-8",
        )
        print(f"Artifacts written to {args.output}", file=sys.stderr)

    print("Submitting artifacts to server for analysis...", file=sys.stderr)
    result = scan_skill_remote(skill_artifacts, args.server)
    if result.get("status") == "error":
        error = result.get("error", "Unknown error")
        print(f"Error: could not retrieve report from server — {error}", file=sys.stderr)
        sys.exit(1)

    print(_format_report(result, local_name=local_name))

    _cleanup_temps(scan_temp_dirs, tmpdir)


def _run_submit(args) -> None:
    """Submit mode: upload archive for deep analysis."""
    print(f"Skill Scanner {SCANNER_VERSION} — submit mode", file=sys.stderr)
    print(f"Resolving target: {args.target}", file=sys.stderr)

    if args.target.startswith("http://") or args.target.startswith("https://"):
        print("Error: Submit mode requires a local directory or zip file, not a URL.", file=sys.stderr)
        sys.exit(1)

    skill_root, tmpdir = resolve_target(args.target)
    print(f"Skill root: {skill_root}", file=sys.stderr)
    print( "This will upload the full skill archive for deep analysis.",file=sys.stderr)

    frontmatter = parse_skill_frontmatter(skill_root)
    skill_name = frontmatter.get("name", "") or skill_root.name

    archive_bytes = pack_skill_zip(skill_root)

    if tmpdir:
        tmpdir.cleanup()

    print(f"Uploading skill {skill_name} for analysis...", file=sys.stderr)
    result = submit_skill_archive(archive_bytes, args.server, skill_name=skill_name)

    if result.get("status") != "success":
        error = result.get("error", "Unknown error")
        print(f"Error: could not submit archive to server — {error}", file=sys.stderr)
        sys.exit(1)

    ack = result.get("ack", {}) or {}
    print(f"Submission accepted for skill '{skill_name}' (status: {ack.get('status', 'queued')}).", file=sys.stderr)
    message = ack.get("message")
    if message:
        print(message, file=sys.stderr)
    else:
        print("Re-run scan mode later to retrieve the verified report.", file=sys.stderr)


def _cleanup_temps(
    scan_temp_dirs: list[tempfile.TemporaryDirectory],
    target_tmpdir: tempfile.TemporaryDirectory | None = None,
) -> None:
    for td in scan_temp_dirs:
        td.cleanup()
    if target_tmpdir:
        target_tmpdir.cleanup()


def main():
    parser = argparse.ArgumentParser(
        description="Agent Skill Scanner — security analysis for agent skills",
    )
    parser.add_argument(
        "target",
        help="Skill directory path, skill name, .zip archive, or skill registry URL",
    )
    parser.add_argument(
        "--mode", "-m",
        choices=["scan", "submit"],
        default="scan",
        help="Operation mode (default: scan)",
    )
    parser.add_argument(
        "--output", "-o",
        help="Write JSON artifacts to this file instead of stdout (scan mode only)",
    )
    parser.add_argument(
        "--server",
        default=DEFAULT_SERVER_URL,
        help=f"Server base URL (default: {DEFAULT_SERVER_URL})",
    )
    parser.add_argument(
        "--no-embeddings",
        action="store_true",
        help="Skip embedding computation",
    )
    parser.add_argument(
        "--no-update",
        action="store_true",
        help="Skip automatic update check",
    )
    args = parser.parse_args()

    if not args.no_update:
        print("Checking for scanner updates...", file=sys.stderr)
        _check_and_apply_update(args.server)

    if args.mode == "submit":
        _run_submit(args)
    else:
        _run_scan(args)

    _show_terms_notice_once()


if __name__ == "__main__":
    main()
