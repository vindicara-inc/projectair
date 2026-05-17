"""Cross-language fidelity fixture generator.

Emits canonical JSON, BLAKE3 content hashes, and Ed25519 signatures for a curated
set of edge-case payloads plus every record from the bundled sample trace. The
TypeScript dashboard verifier must reproduce these byte-for-byte; if it cannot,
every signature fails to verify in the browser and the demo dies.

Run from the repo root with the editable airsdk install active:

    python packages/air-dashboard/tests/fixtures/generate.py

Writes (committed):
    packages/air-dashboard/tests/fixtures/canonical-fixtures.json
    packages/air-dashboard/tests/fixtures/sample-trace-cases.json

Known limitation: AgDRPayload's typed fields are string-heavy. Float-vs-int
distinction (Python "1.0" vs JS "1") would diverge if floats appeared in
`tool_args`. The current sample trace contains no floats, so Phase 0 is safe;
the TypeScript canonicalizer documents this case as a follow-up.
"""
from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from airsdk.agdr import GENESIS_PREV_HASH, _blake3_hex, _canonical_json, load_chain
from airsdk.types import AgDRPayload

# Deterministic key for reproducible signature fixtures across runs and machines.
DETERMINISTIC_SEED_HEX = "1234567890abcdef" * 4  # 64 hex chars = 32 bytes
_SIGNING_KEY = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(DETERMINISTIC_SEED_HEX))
_SIGNER_KEY_HEX = _SIGNING_KEY.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()

REPO_ROOT = Path(__file__).resolve().parents[4]
SAMPLE_TRACE = REPO_ROOT / "packages" / "projectair" / "examples" / "sample_trace.log"
OUT_DIR = Path(__file__).resolve().parent


@dataclass
class FidelityCase:
    name: str
    description: str
    input_payload: dict[str, Any]
    canonical_bytes_hex: str
    content_hash: str
    prev_hash: str
    signature_hex: str
    signer_key_hex: str


@dataclass
class SampleTraceCase:
    """One record extracted verbatim from the bundled sample trace.

    Unlike `FidelityCase`, the signature here was produced by a fresh ephemeral
    key when the trace was generated; we cannot reproduce it. Tests must verify
    the bundled signature against the bundled signer_key.
    """

    index: int
    step_id: str
    kind: str
    prev_hash: str
    expected_content_hash: str
    payload_for_canonicalization: dict[str, Any]
    signature_hex: str
    signer_key_hex: str


def _build_case(
    name: str,
    description: str,
    payload: dict[str, Any],
    prev_hash: str = GENESIS_PREV_HASH,
) -> FidelityCase:
    """Construct one fidelity case using the same pipeline airsdk runs."""
    cleaned = AgDRPayload.model_validate(payload).model_dump(exclude_none=True)
    canonical = _canonical_json(cleaned)
    content_hash = _blake3_hex(canonical)
    sig_material = bytes.fromhex(prev_hash) + bytes.fromhex(content_hash)
    signature = _SIGNING_KEY.sign(sig_material).hex()
    return FidelityCase(
        name=name,
        description=description,
        input_payload=payload,
        canonical_bytes_hex=canonical.hex(),
        content_hash=content_hash,
        prev_hash=prev_hash,
        signature_hex=signature,
        signer_key_hex=_SIGNER_KEY_HEX,
    )


def _build_curated_cases() -> list[FidelityCase]:
    """Edge-case payloads the TypeScript canonicalizer must round-trip exactly."""
    cases: list[FidelityCase] = [
        _build_case(
            "simple_prompt",
            "Smallest realistic payload. Single ASCII string field.",
            {"prompt": "hello"},
        ),
        _build_case(
            "key_ordering_at_root",
            "AgDRPayload sorts keys alphabetically; tests `response` precedes `tool_name` etc.",
            {"tool_name": "z_last", "prompt": "a_first"},
        ),
        _build_case(
            "exclude_none_strips_unset_fields",
            "Pydantic `exclude_none=True` removes explicit None values before canonicalization.",
            {"prompt": "kept", "response": None, "tool_name": None},
        ),
        _build_case(
            "user_intent_carried_through",
            "Common case: recorder injects user_intent into every payload.",
            {"prompt": "x", "user_intent": "Refactor the auth module"},
        ),
        _build_case(
            "emoji_and_non_bmp",
            "UTF-8 sequences outside the Basic Multilingual Plane. JS surrogate pairs must encode identically.",
            {"prompt": "🔐 secrets 😀 chain 🛰️ done"},
        ),
        _build_case(
            "cjk_content",
            "Chinese/Japanese/Korean characters round-trip via UTF-8 without escaping.",
            {"prompt": "你好世界 こんにちは 안녕하세요"},
        ),
        _build_case(
            "rtl_arabic",
            "Right-to-left script encoded as UTF-8 (no BiDi marker normalization).",
            {"prompt": "مرحبا بك في النظام"},
        ),
        _build_case(
            "embedded_control_chars",
            "Newlines, tabs, and quotes use JSON escape sequences in both languages.",
            {"prompt": 'line1\nline2\twith "quote" and \\backslash'},
        ),
        _build_case(
            "tool_args_nested_object",
            "tool_args is dict[str, Any]; nested dicts must also have keys sorted recursively.",
            {
                "tool_name": "search",
                "tool_args": {
                    "z_outer": {"z_inner": 1, "a_inner": 2},
                    "a_outer": ["item_b", "item_a"],
                },
            },
        ),
        _build_case(
            "tool_args_empty_object",
            "Empty {} and [] must serialize as `{}` and `[]` (no whitespace).",
            {"tool_name": "noop", "tool_args": {}},
        ),
        _build_case(
            "tool_args_mixed_array",
            "Arrays preserve order (JSON arrays are ordered); strings inside follow same UTF-8 rules.",
            {"tool_name": "x", "tool_args": {"items": ["alpha", "beta", "🔐"]}},
        ),
        _build_case(
            "agent_message_fields",
            "ASI07 inter-agent communication payload shape.",
            {
                "source_agent_id": "agent-a",
                "target_agent_id": "agent-b",
                "message_id": "01HXYZ12345",
                "message_content": "ack",
            },
        ),
        _build_case(
            "agent_finish_with_final_output",
            "Terminal record kind that closes a session.",
            {"final_output": "Sales report emailed.", "user_intent": "Draft a Q3 sales report"},
        ),
        _build_case(
            "deeply_nested_tool_args",
            "Three levels of nesting; key order at every level must be alphabetical.",
            {
                "tool_name": "deep",
                "tool_args": {
                    "outer": {
                        "middle": {
                            "z_leaf": "z",
                            "a_leaf": "a",
                            "m_leaf": {"nested_z": True, "nested_a": False},
                        }
                    }
                },
            },
        ),
        _build_case(
            "non_genesis_prev_hash",
            "Mid-chain record: prev_hash is a real BLAKE3 digest, not all zeros.",
            {"prompt": "step 5"},
            prev_hash="a" * 64,
        ),
    ]
    return cases


def _build_sample_trace_cases() -> list[SampleTraceCase]:
    """Extract every record from the bundled trace as a verification fixture."""
    if not SAMPLE_TRACE.exists():
        raise FileNotFoundError(
            f"sample trace missing at {SAMPLE_TRACE}; run from repo root with editable install"
        )
    records = load_chain(SAMPLE_TRACE)
    cases: list[SampleTraceCase] = []
    for index, record in enumerate(records):
        payload_for_canonical = record.payload.model_dump(exclude_none=True)
        cases.append(
            SampleTraceCase(
                index=index,
                step_id=record.step_id,
                kind=record.kind.value,
                prev_hash=record.prev_hash,
                expected_content_hash=record.content_hash,
                payload_for_canonicalization=payload_for_canonical,
                signature_hex=record.signature,
                signer_key_hex=record.signer_key,
            )
        )
    return cases


def _write_json(path: Path, body: dict[str, Any]) -> None:
    """Pretty-print fixtures with UTF-8 preserved (ensure_ascii=False)."""
    path.write_text(json.dumps(body, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def main() -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)

    curated = _build_curated_cases()
    curated_path = OUT_DIR / "canonical-fixtures.json"
    _write_json(
        curated_path,
        {
            "schema_version": "1",
            "generator": "packages/air-dashboard/tests/fixtures/generate.py",
            "deterministic_seed_hex": DETERMINISTIC_SEED_HEX,
            "signer_key_hex": _SIGNER_KEY_HEX,
            "genesis_prev_hash": GENESIS_PREV_HASH,
            "cases": [asdict(case) for case in curated],
        },
    )

    sample = _build_sample_trace_cases()
    sample_path = OUT_DIR / "sample-trace-cases.json"
    _write_json(
        sample_path,
        {
            "schema_version": "1",
            "generator": "packages/air-dashboard/tests/fixtures/generate.py",
            "source_log": str(SAMPLE_TRACE.relative_to(REPO_ROOT)),
            "cases": [asdict(case) for case in sample],
        },
    )

    print(f"wrote {len(curated)} curated cases to {curated_path.relative_to(REPO_ROOT)}")
    print(f"wrote {len(sample)} sample-trace cases to {sample_path.relative_to(REPO_ROOT)}")


if __name__ == "__main__":
    main()
