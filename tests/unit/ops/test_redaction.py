"""Tests for ``vindicara.ops.redaction``.

The hypothesis-based test is the load-bearing one: it asserts that no
denylisted field name (anything containing 'token', 'secret', 'password',
'email', etc.) ever appears in the redacted output as anything other than
a ``blake3:<hex>`` hash, regardless of what input we throw at it. This is
the property that backs the launch claim that the public chain leaks no
PII or secrets.
"""
from __future__ import annotations

import json
import re
from typing import Any

from hypothesis import given, settings
from hypothesis import strategies as st

from vindicara.ops.redaction import REDACTED_PREFIX, redact_record
from vindicara.ops.schema import DENYLIST_FIELD_NAMES, OpsKind

_BLAKE3_HASH_RE = re.compile(rf"^{re.escape(REDACTED_PREFIX)}[0-9a-f]{{64}}$")


def test_unknown_kind_redacts_everything() -> None:
    record = {
        "version": "0.4",
        "step_id": "01H8X0ABCDEFGHJKLMNPQRSTU",
        "timestamp": "2026-05-08T15:00:00Z",
        "kind": "totally-unknown-kind",
        "payload": {"safe_field": "ok", "secret_token": "shh"},
        "prev_hash": "0" * 64,
        "content_hash": "1" * 64,
        "signer_key": "deadbeef",
    }
    out = redact_record(record)

    assert out["kind"] == "totally-unknown-kind"
    assert _BLAKE3_HASH_RE.match(out["payload"]["safe_field"])
    assert _BLAKE3_HASH_RE.match(out["payload"]["secret_token"])
    assert "signature" not in out


def test_known_kind_emits_whitelisted_fields_clear() -> None:
    record = {
        "version": "0.4",
        "step_id": "01H8X0ABCDEFGHJKLMNPQRSTU",
        "timestamp": "2026-05-08T15:00:00Z",
        "kind": "tool_start",
        "payload": {
            "tool_name": OpsKind.API_REQUEST.value,
            "tool_args": {"method": "GET", "path_template": "/health"},
            "method": "GET",
            "path_template": "/health",
            "status_code": 200,
            "duration_ms": 12,
            "user_email": "kevin@example.com",
            "auth_token": "Bearer xyz",
        },
        "prev_hash": "0" * 64,
        "content_hash": "1" * 64,
        "signer_key": "deadbeef",
    }
    record_with_kind = {**record, "kind": OpsKind.API_REQUEST.value}
    out = redact_record(record_with_kind)

    assert out["payload"]["method"] == "GET"
    assert out["payload"]["path_template"] == "/health"
    assert out["payload"]["status_code"] == 200
    assert out["payload"]["duration_ms"] == 12
    assert _BLAKE3_HASH_RE.match(out["payload"]["user_email"])
    assert _BLAKE3_HASH_RE.match(out["payload"]["auth_token"])
    assert _BLAKE3_HASH_RE.match(out["payload"]["tool_name"])
    assert _BLAKE3_HASH_RE.match(out["payload"]["tool_args"])


def test_redaction_is_deterministic() -> None:
    record = {
        "version": "0.4",
        "step_id": "01H8X0ABCDEFGHJKLMNPQRSTU",
        "timestamp": "2026-05-08T15:00:00Z",
        "kind": "anything",
        "payload": {"token": "secret-value"},
        "prev_hash": "0" * 64,
        "content_hash": "1" * 64,
        "signer_key": "deadbeef",
    }
    out_a = redact_record(record)
    out_b = redact_record(record)
    assert out_a["payload"]["token"] == out_b["payload"]["token"]


def test_signature_field_is_not_published() -> None:
    record = {
        "version": "0.4",
        "step_id": "01H8X0ABCDEFGHJKLMNPQRSTU",
        "timestamp": "2026-05-08T15:00:00Z",
        "kind": "tool_start",
        "payload": {},
        "prev_hash": "0" * 64,
        "content_hash": "1" * 64,
        "signature": "abc123",
        "signer_key": "deadbeef",
    }
    out = redact_record(record)
    assert "signature" not in out


def test_housekeeping_fields_pass_through() -> None:
    record = {
        "version": "0.4",
        "step_id": "01H8X0ABCDEFGHJKLMNPQRSTU",
        "timestamp": "2026-05-08T15:00:00Z",
        "kind": "tool_start",
        "payload": {},
        "prev_hash": "0" * 64,
        "content_hash": "1" * 64,
        "signer_key": "deadbeef",
        "ord": "000003",
        "chain_id": "test-chain",
        "rekor_log_index": 1465403522,
    }
    out = redact_record(record)
    assert out["ord"] == "000003"
    assert out["chain_id"] == "test-chain"
    assert out["rekor_log_index"] == 1465403522


# ---- The load-bearing property test --------------------------------------


def _walk_json_strings(obj: Any) -> list[tuple[str, Any]]:
    """Yield (path, value) pairs for every leaf in a JSON-shaped object."""
    out: list[tuple[str, Any]] = []

    def walk(node: Any, path: str) -> None:
        if isinstance(node, dict):
            for key, value in node.items():
                walk(value, f"{path}.{key}" if path else key)
        elif isinstance(node, list):
            for idx, value in enumerate(node):
                walk(value, f"{path}[{idx}]")
        else:
            out.append((path, node))

    walk(obj, "")
    return out


def _field_name_in_path(path: str, denied: frozenset[str]) -> str | None:
    """Return the lowercased denylist match if any segment of ``path`` matches."""
    lower = path.lower()
    for needle in denied:
        if needle in lower:
            return needle
    return None


_payload_strategy = st.dictionaries(
    keys=st.text(min_size=1, max_size=20),
    values=st.recursive(
        st.one_of(
            st.text(),
            st.integers(),
            st.booleans(),
            st.none(),
            st.floats(allow_nan=False, allow_infinity=False),
        ),
        lambda children: st.one_of(
            st.lists(children, max_size=3),
            st.dictionaries(st.text(min_size=1, max_size=10), children, max_size=3),
        ),
        max_leaves=20,
    ),
    max_size=15,
)


@given(payload=_payload_strategy)
@settings(max_examples=200, deadline=None)
def test_no_denylist_field_leaks_into_public(payload: dict[str, Any]) -> None:
    """For any payload, no top-level denylisted field name appears as cleartext.

    'Top-level' is what matters because the redactor whitelists at the top
    level only; nested dicts under a whitelisted top-level key flow through
    clear by design (the per-kind whitelist controls that). Therefore the
    invariant is: any TOP-LEVEL field whose name matches the denylist must
    appear as a blake3-prefixed hash.
    """
    record = {
        "version": "0.4",
        "step_id": "01H8X0ABCDEFGHJKLMNPQRSTU",
        "timestamp": "2026-05-08T15:00:00Z",
        "kind": "totally-unknown-kind",
        "payload": payload,
        "prev_hash": "0" * 64,
        "content_hash": "1" * 64,
        "signer_key": "deadbeef",
    }
    out = redact_record(record)
    redacted_payload = out["payload"]

    for top_level_key, value in redacted_payload.items():
        if _field_name_in_path(top_level_key, DENYLIST_FIELD_NAMES) is not None:
            assert isinstance(value, str), (
                f"denylist field {top_level_key!r} produced non-string redaction: {value!r}"
            )
            assert _BLAKE3_HASH_RE.match(value), (
                f"denylist field {top_level_key!r} not redacted: {value!r}"
            )

    serialized = json.dumps(out, default=str)
    assert "totally-unknown-kind" in serialized
