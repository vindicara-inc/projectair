"""Per-kind redaction policy applied at publication time.

The internal chain (DynamoDB) keeps full payload fidelity. The public chain
(S3 JSONL at ``vindicara.io/ops-chain/``) is what this module produces. Two
properties matter:

1. **Default deny.** Any payload field not explicitly listed in
   :data:`vindicara.ops.schema.REDACTION_POLICY` for the record's kind is
   replaced by ``"blake3:" || hex_mac`` of the original value's canonical
   JSON encoding. The MAC is a keyed BLAKE3 digest under a per-deployment
   secret (``VINDICARA_REDACTION_KEY``), not a bare hash, so short low-entropy
   PII (SSN, MRN, phone, DOB) cannot be brute-forced back out of the public
   chain. The key is stable per deployment, preserving same-input-same-digest
   correlation. This includes nested fields (the redactor walks dicts and
   lists recursively) so a future schema addition does not silently leak
   into the public chain.

2. **Signature integrity is not preserved.** The published JSONL is for
   forensic narrative, not chain verification. The Sigstore Rekor anchor
   covers the *internal* chain root over the unredacted records. Public
   verifiers that want to assert "this Rekor entry covers what Vindicara
   says it does" verify the published manifest's anchor, not the JSONL
   bodies. The published JSONL carries each record's ``step_id``,
   ``timestamp``, ``kind``, ``ord``, redacted payload, and the Rekor log
   index that anchors the chain it belongs to.
"""

from __future__ import annotations

import functools
import json
import os
from typing import Any

import blake3

from vindicara.ops.schema import PUBLIC_FIELDS_DEFAULT, REDACTION_POLICY

REDACTED_PREFIX = "blake3:"

# Per-deployment secret that keys the redaction MAC. Without it, a redacted
# field is a plain BLAKE3 digest of the original value, which is trivially
# brute-forceable for low-entropy PII (a 9-digit SSN is only 10^9 candidates,
# seconds on commodity hardware). Keying with a deployment secret preserves the
# same-input-same-digest correlation property the public chain relies on while
# making the digests unrecoverable to anyone who does not hold the secret.
# The secret must be stable for the life of a chain: rotating it breaks
# cross-record correlation for records hashed under the old key.
_REDACTION_KEY_ENV = "VINDICARA_REDACTION_KEY"
_KDF_CONTEXT = "vindicara.ops.redaction MAC key v1"


class RedactionKeyError(RuntimeError):
    """Raised when the per-deployment redaction secret is required but unset."""


@functools.lru_cache(maxsize=4)
def _derive_key(secret: str) -> bytes:
    """Derive a 32-byte BLAKE3 MAC key from the deployment secret via BLAKE3 KDF."""
    return blake3.blake3(secret.encode("utf-8"), derive_key_context=_KDF_CONTEXT).digest()


def _redaction_key() -> bytes:
    """Return the 32-byte MAC key, failing closed if the secret is not configured."""
    secret = os.environ.get(_REDACTION_KEY_ENV)
    if not secret:
        raise RedactionKeyError(
            f"{_REDACTION_KEY_ENV} is not set. Public-chain redaction requires a "
            "stable, high-entropy per-deployment secret so short PII (SSN, MRN, "
            "phone, DOB) cannot be brute-forced from the published BLAKE3 hashes. "
            "Set it in the ops-chain publisher environment before publishing."
        )
    return _derive_key(secret)


def _hash_value(value: Any) -> str:
    """Return the keyed-BLAKE3 MAC of ``value`` as ``"blake3:<hex>"``.

    Uses sorted keys + no whitespace so the same logical value produces the
    same digest regardless of dict iteration order or float reformatting. The
    digest is keyed with the per-deployment secret (see :func:`_redaction_key`),
    so it is a MAC, not a bare hash: identical within a deployment for
    correlation, but not reversible by brute force without the secret.
    """
    canonical = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)
    digest = blake3.blake3(canonical.encode("utf-8"), key=_redaction_key()).hexdigest()
    return REDACTED_PREFIX + digest


def _redact_payload(payload: dict[str, Any], public_fields: frozenset[str]) -> dict[str, Any]:
    """Recursively redact a payload dict against the per-kind public-field set.

    Top-level keys not in ``public_fields`` are replaced by their hash. Top-level
    keys in ``public_fields`` are emitted clear (their values pass through
    unchanged, including nested structures).
    """
    redacted: dict[str, Any] = {}
    for key, value in payload.items():
        if key in public_fields:
            redacted[key] = value
        else:
            redacted[key] = _hash_value(value)
    return redacted


def effective_kind(record: dict[str, Any]) -> str:
    """Return the kind to use for redaction policy lookup.

    AgDR's :class:`airsdk.types.StepKind` is a closed enum (``tool_start``,
    ``tool_end``, etc.) so Vindicara-specific event taxonomies live in the
    payload's ``tool_name`` field. For redaction we want to apply policy
    by the Vindicara taxonomy (e.g. ``vindicara.api.request``), not by
    the generic AgDR step kind. This helper unifies the two: when the
    record is a tool_start / tool_end, we use ``tool_name``; otherwise
    we use the AgDR kind directly.
    """
    kind = str(record.get("kind", ""))
    if kind in ("tool_start", "tool_end"):
        payload = record.get("payload", {})
        if isinstance(payload, dict):
            tool_name = payload.get("tool_name")
            if isinstance(tool_name, str) and tool_name:
                return tool_name
    return kind


def redact_record(record: dict[str, Any]) -> dict[str, Any]:
    """Redact one record dict for publication.

    Input is the AgDR record as parsed from the internal chain (i.e. the
    output of ``AgDRRecord.model_dump(mode="json")``). Output is a new
    dict suitable for writing into the public JSONL.

    Top-level fields kept clear: ``version``, ``step_id``, ``timestamp``,
    ``kind``, ``prev_hash``, ``content_hash``, ``signer_key``, plus the
    internal-chain housekeeping fields (``ord``, ``chain_id``,
    ``rekor_log_index``) when present. The ``signature`` is dropped from
    the public copy because the public copy's payload is not the bytes the
    signature covers (the signature covered the unredacted content_hash).
    The ``content_hash`` and ``prev_hash`` from the internal record stay
    intact so a verifier can still confirm chain ordering against the
    Rekor anchor.

    Payload fields are filtered through the per-effective-kind whitelist
    (see :func:`effective_kind`). Unknown effective kinds default to
    publishing nothing beyond the housekeeping fields.
    """
    kind = str(record.get("kind", ""))
    lookup_kind = effective_kind(record)
    public_fields = REDACTION_POLICY.get(lookup_kind, PUBLIC_FIELDS_DEFAULT)
    raw_payload = record.get("payload", {})
    payload = raw_payload if isinstance(raw_payload, dict) else {}

    redacted_record: dict[str, Any] = {
        "version": record.get("version"),
        "step_id": record.get("step_id"),
        "timestamp": record.get("timestamp"),
        "kind": kind,
        "payload": _redact_payload(payload, public_fields),
        "prev_hash": record.get("prev_hash"),
        "content_hash": record.get("content_hash"),
        "signer_key": record.get("signer_key"),
    }

    for housekeeping in ("ord", "chain_id", "rekor_log_index"):
        if housekeeping in record:
            redacted_record[housekeeping] = record[housekeeping]

    return redacted_record
