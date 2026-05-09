"""Per-kind redaction policy applied at publication time.

The internal chain (DynamoDB) keeps full payload fidelity. The public chain
(S3 JSONL at ``vindicara.io/ops-chain/``) is what this module produces. Two
properties matter:

1. **Default deny.** Any payload field not explicitly listed in
   :data:`vindicara.ops.schema.REDACTION_POLICY` for the record's kind is
   replaced by ``"blake3:" || hex_digest`` of the original value's canonical
   JSON encoding. This includes nested fields (the redactor walks dicts and
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

import json
from typing import Any

import blake3

from vindicara.ops.schema import PUBLIC_FIELDS_DEFAULT, REDACTION_POLICY

REDACTED_PREFIX = "blake3:"


def _hash_value(value: Any) -> str:
    """Return the canonical-JSON BLAKE3 hash of ``value`` as ``"blake3:<hex>"``.

    Uses sorted keys + no whitespace so the same logical value produces the
    same hash regardless of dict iteration order or float reformatting.
    """
    canonical = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)
    digest = blake3.blake3(canonical.encode("utf-8")).hexdigest()
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
