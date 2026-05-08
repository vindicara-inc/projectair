"""RFC 8785 JCS canonicalization + BLAKE3 hashing per Section 15.11.

Strict input policy: only JSON-native primitives are accepted
(dict, list, str, int, float, bool, None). Any other type raises
CanonicalizationError. This is the only way to guarantee identical
hashes across Python, Go, Rust, and JavaScript implementations of
the AgDR Handoff Protocol.

Callers are responsible for pre-normalizing custom types:
    - bytes      -> base64url unpadded string
    - datetime   -> RFC 3339 UTC with 'Z' suffix
    - UUID       -> str(uuid)  (lowercase, hyphenated)
    - Decimal    -> str(decimal)
    - Enum       -> enum.value
    - pathlib    -> as_posix()
"""
from __future__ import annotations

from typing import Any

import jcs  # type: ignore[import-untyped]
from blake3 import blake3

from .exceptions import CanonicalizationError

# Reference hash values from Section 6.6, locked.
_EMPTY_NULL_HASH = "blake3:" + blake3(b"").hexdigest()
_EMPTY_OBJECT_HASH = "blake3:" + blake3(b"{}").hexdigest()
_EMPTY_ARRAY_HASH = "blake3:" + blake3(b"[]").hexdigest()


def _validate_json_primitives(payload: Any, _path: str = "$") -> None:
    """Recursively confirm payload contains only JSON-native types.

    Raises CanonicalizationError with a JSONPath-style location on the
    first non-primitive found, so callers can fix the offending field.
    """
    # bool is a subclass of int in Python; check it before the int branch
    # to avoid silently demoting True/False to 1/0 in error messages.
    if isinstance(payload, bool) or payload is None:
        return
    if isinstance(payload, (str, int, float)):
        return
    if isinstance(payload, dict):
        for k, v in payload.items():
            if not isinstance(k, str):
                raise CanonicalizationError(
                    f"non-string dict key at {_path}: {type(k).__name__}"
                )
            _validate_json_primitives(v, f"{_path}.{k}")
        return
    if isinstance(payload, list):
        for i, item in enumerate(payload):
            _validate_json_primitives(item, f"{_path}[{i}]")
        return
    raise CanonicalizationError(
        f"non-JSON-primitive type at {_path}: {type(payload).__name__}. "
        f"Caller must pre-normalize (bytes->base64, datetime->RFC3339, "
        f"UUID/Decimal/Enum->str, etc.) before canonicalize_and_hash()."
    )


def canonicalize_and_hash(payload: Any) -> str:
    """Compute BLAKE3(JCS(payload)) per Section 15.11 of the Layer 4 spec.

    Enforces the canonical empty payload conventions of Section 6.6.
    Rejects non-JSON-primitive inputs with a precise JSONPath diagnostic.
    """
    # Convention 1: no payload (None / absent)
    if payload is None:
        return _EMPTY_NULL_HASH

    # Convention 2: empty object - strict isinstance check, not == {}
    if isinstance(payload, dict) and len(payload) == 0:
        return _EMPTY_OBJECT_HASH

    # Convention 3: empty array - strict isinstance check, not == []
    # tuples are NOT lists in JSON; they must be normalized by the caller
    # if they want array semantics.
    if isinstance(payload, list) and len(payload) == 0:
        return _EMPTY_ARRAY_HASH

    # Standard path: validate, JCS, BLAKE3
    _validate_json_primitives(payload)
    try:
        canonical_bytes = jcs.canonicalize(payload)
    except Exception as e:
        raise CanonicalizationError(f"RFC 8785 canonicalization failed: {e}") from e

    digest = blake3(canonical_bytes).hexdigest()
    return f"blake3:{digest}"


def canonicalize_bytes(payload: Any) -> bytes:
    """Return the RFC 8785 JCS canonical bytes for ``payload``.

    Used in places that need the canonical bytes themselves (e.g. signing
    over canonical content, not just the digest). Subject to the same
    strict input policy as :func:`canonicalize_and_hash`.
    """
    if payload is None:
        return b""
    if isinstance(payload, dict) and len(payload) == 0:
        return b"{}"
    if isinstance(payload, list) and len(payload) == 0:
        return b"[]"
    _validate_json_primitives(payload)
    try:
        canonical: bytes = jcs.canonicalize(payload)
    except Exception as e:
        raise CanonicalizationError(f"RFC 8785 canonicalization failed: {e}") from e
    return canonical


def hash_bytes(data: bytes) -> str:
    """Return the canonical ``blake3:<hex>`` digest of raw bytes.

    Used for hashing already-canonical material (cap-token JWS strings,
    certificate DER, etc.) where there is no JSON object to canonicalize.
    """
    return f"blake3:{blake3(data).hexdigest()}"


__all__ = [
    "canonicalize_and_hash",
    "canonicalize_bytes",
    "hash_bytes",
]
