"""Embedding extraction for skill files using light_embed (ONNX).

Uses sentence-transformers/all-MiniLM-L6-v2 with overlapping-chunk
mean pooling.  When ``logging`` is configured (server context) warnings
go through the standard logger; otherwise they fall back to stderr.
"""

import contextlib
import io
import logging
import sys
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeoutError
from pathlib import Path

import numpy as np

try:
    from light_embed import TextEmbedding
    from tokenizers import Tokenizer

    HAS_EMBED = True
except ImportError:
    HAS_EMBED = False

logger = logging.getLogger(__name__)

MODEL_NAME = "sentence-transformers/all-MiniLM-L6-v2"
_MODEL = None
_TOKENIZER = None

MODEL_LOAD_TIMEOUT_S = 120
PER_FILE_TIMEOUT_S = 30


def _warn(msg: str) -> None:
    """Emit a warning via the logger if handlers are configured, else stderr."""
    if logger.handlers or logging.root.handlers:
        logger.warning(msg)
    else:
        print(f"  [WARN] {msg}", file=sys.stderr)


def _get_model_and_tokenizer():
    """Lazy-load the embedding model and tokenizer on first use."""
    global _MODEL, _TOKENIZER
    if _MODEL is None:
        with contextlib.redirect_stderr(io.StringIO()):
            _MODEL = TextEmbedding(model_name_or_path=MODEL_NAME)
        _TOKENIZER = Tokenizer.from_pretrained(MODEL_NAME)
        _TOKENIZER.no_truncation()
    return _MODEL, _TOKENIZER


def _embed_text(text: str):
    """Return a single embedding vector for an arbitrarily long text.

    Short texts are encoded in one pass.  Longer texts are split into
    overlapping token-level chunks whose embeddings are mean-pooled.
    """
    model, tokenizer = _get_model_and_tokenizer()
    chunk_size = getattr(model, "max_seq_length", None) or 256
    chunk_size -= 2  # reserve [CLS] / [SEP]
    overlap = min(64, chunk_size // 2)
    stride = chunk_size - overlap

    tokens = tokenizer.encode(text, add_special_tokens=False).ids
    if len(tokens) <= chunk_size:
        return model.encode([text])[0]

    chunks = []
    for start in range(0, len(tokens), stride):
        chunk_tokens = tokens[start : start + chunk_size]
        chunks.append(tokenizer.decode(chunk_tokens))

    embeddings = model.encode(chunks)
    return np.mean(embeddings, axis=0)


def _run_with_timeout(fn, timeout_s, label="operation"):
    """Run *fn* in a thread with a timeout; returns result or raises."""
    with ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(fn)
        try:
            return future.result(timeout=timeout_s)
        except FuturesTimeoutError:
            raise TimeoutError(f"{label} timed out after {timeout_s}s")


def compute_embeddings(entries: list[dict], read_text_fn) -> None:
    """Compute embeddings for text file entries in-place.

    Args:
        entries: file entry dicts (must have "_abs_path" key).
        read_text_fn: callable(Path) -> str|None — used to read text content.
            Non-text files (where this returns None) get embedding=None.
    """
    if not HAS_EMBED:
        _warn("light_embed not installed, skipping embeddings")
        for entry in entries:
            entry["embedding"] = None
        return

    try:
        _run_with_timeout(_get_model_and_tokenizer, MODEL_LOAD_TIMEOUT_S, "Model loading")
    except Exception as exc:
        _warn(f"Failed to load embedding model: {exc}")
        for entry in entries:
            entry["embedding"] = None
        return

    for entry in entries:
        abs_path = Path(entry["_abs_path"])
        try:
            text = read_text_fn(abs_path) if abs_path.is_file() else None
        except Exception as exc:
            _warn(f"Could not read {abs_path.name}: {exc}")
            entry["embedding"] = None
            continue

        if not text or not text.strip():
            entry["embedding"] = None
            continue

        try:
            vec = _run_with_timeout(
                lambda t=text: _embed_text(t), PER_FILE_TIMEOUT_S, f"Embedding {abs_path.name}"
            )
            entry["embedding"] = vec.tolist() if hasattr(vec, "tolist") else list(vec)
        except Exception as exc:
            _warn(f"Embedding failed for {abs_path.name}: {exc}")
            entry["embedding"] = None


def compute_embeddings_for_dir(skill_dir: Path) -> list[dict]:
    """Compute embeddings for all text files in a skill directory.

    Builds file entries from *skill_dir*, computes embeddings, and
    returns a list of ``{"path": ..., "embedding": [...]}`` dicts.
    """
    TEXT_EXTENSIONS = {".md", ".py", ".sh", ".bash", ".js", ".ts", ".yaml", ".yml", ".json", ".txt"}
    MAX_FILE_BYTES = 2 * 1024 * 1024

    entries: list[dict] = []
    for fpath in sorted(skill_dir.rglob("*")):
        if not fpath.is_file():
            continue
        if fpath.suffix.lower() not in TEXT_EXTENSIONS:
            continue
        entries.append({
            "path": str(fpath.relative_to(skill_dir)),
            "_abs_path": str(fpath),
        })

    def _read_text(path: Path) -> str | None:
        try:
            if path.stat().st_size > MAX_FILE_BYTES:
                return None
            return path.read_text(encoding="utf-8", errors="replace")
        except Exception:
            return None

    compute_embeddings(entries, _read_text)

    for entry in entries:
        entry.pop("_abs_path", None)

    return entries
