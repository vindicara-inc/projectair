"""Verification of GPU_ATTESTATION records (W1, experimental).

Adds the attestation check to ``air verify-public``. When a chain carries a
GPU_ATTESTATION record, four things are checked, each against a root that is
not Vindicara:

1. The genesis-derived nonce recomputes from the chain and equals the
   recorded nonce (replay defense; fails closed).
2. The NRAS EAT signature verifies: online against NRAS JWKS, or offline
   against a cached NVIDIA attestation signing certificate. The EAT's nonce
   claim must equal the recorded nonce.
3. ``rim_matched`` is true and the per-device EAT bundle is consistent with
   the overall detached EAT.
4. The GPU_ATTESTATION record falls inside an anchored step range, so the
   attestation is provably under a Rekor-anchored root.

Failures are fatal to the attestation claim but do not retroactively
invalidate the rest of the chain; per-root status is reported so a buyer
sees exactly which guarantees hold.

Offline note: the canonical cached reference set (signing cert, RIM, OCSP)
and its rotation cadence is a W1 open decision locked with NVIDIA
(spec 2.8). The provisional OCSP reference format is a JSON object with a
``status`` field that must equal ``"good"``.
"""
from __future__ import annotations

import json
from pathlib import Path

import jwt as pyjwt
from cryptography.x509 import load_pem_x509_certificate

from airsdk.attestation.config import GPUAttestationConfig, VerifyMode
from airsdk.attestation.evidence import verify_nonce
from airsdk.attestation.types import AttestationVerification, GPUAttestation
from airsdk.types import AgDRRecord, StepKind

__all__ = ["verify_attestation"]

_ACCEPTED_EAT_ALGS = ["ES384", "ES256", "RS256"]
_NONCE_CLAIMS = ("eat_nonce", "x-nvidia-nonce", "nonce")
_DEVICE_COUNT_CLAIMS = ("x-nvidia-num-devices", "device_count")


def verify_attestation(
    records: list[AgDRRecord],
    *,
    mode: VerifyMode,
    config: GPUAttestationConfig | None = None,
) -> AttestationVerification:
    """Run the attestation checks over ``records``.

    Chains without a GPU_ATTESTATION record pass with zero records checked,
    so legacy chains stay green.
    """
    resolved = config if config is not None else GPUAttestationConfig(mode=mode)
    attestation_records = [r for r in records if r.kind == StepKind.GPU_ATTESTATION]
    passed: list[str] = []
    failures: list[str] = []
    if not attestation_records:
        return AttestationVerification(
            ok=True, mode=mode, records_checked=0, checks_passed=[], failures=[]
        )

    genesis = records[0]
    if genesis.kind != StepKind.DELEGATION:
        failures.append(
            "attestation requires a DELEGATION genesis record; chain root is "
            f"{genesis.kind}"
        )
    for record in attestation_records:
        _check_record(record, genesis, mode, resolved, passed, failures)
        _check_anchor_coverage(record, records, passed, failures)

    return AttestationVerification(
        ok=not failures,
        mode=mode,
        records_checked=len(attestation_records),
        checks_passed=passed,
        failures=failures,
    )


def _check_record(
    record: AgDRRecord,
    genesis: AgDRRecord,
    mode: VerifyMode,
    config: GPUAttestationConfig,
    passed: list[str],
    failures: list[str],
) -> None:
    attestation = record.payload.attestation
    if attestation is None:
        failures.append(f"step {record.step_id}: GPU_ATTESTATION record carries no attestation")
        return

    # Check 1: nonce binds to chain genesis. Fails closed on any malformed input.
    if genesis.kind == StepKind.DELEGATION and verify_nonce(
        attestation.nonce, genesis.content_hash
    ):
        passed.append("nonce_binds_to_genesis")
    else:
        failures.append(
            f"step {record.step_id}: nonce does not recompute from the DELEGATION "
            "genesis content hash (replay defense, fails closed)"
        )
        return

    # Check 2: EAT signature plus nonce claim.
    try:
        claims = _decode_eat(attestation, mode, config)
    except Exception as exc:
        failures.append(f"step {record.step_id}: EAT signature verification failed: {exc}")
        return
    passed.append(f"eat_signature_{mode}")

    eat_nonce = _first_claim(claims, _NONCE_CLAIMS)
    if eat_nonce == attestation.nonce:
        passed.append("eat_nonce_matches_record")
    else:
        failures.append(
            f"step {record.step_id}: EAT nonce claim {eat_nonce!r} does not equal "
            "the recorded chain-bound nonce"
        )
        return

    # Check 3: RIM verdict and device bundle consistency.
    overall = claims.get("x-nvidia-overall-att-result")
    if attestation.rim_matched and overall not in (False, "FAIL"):
        passed.append("rim_matched")
    else:
        failures.append(
            f"step {record.step_id}: evidence did not match the Reference "
            f"Integrity Manifest (rim_matched={attestation.rim_matched}, "
            f"overall={overall!r})"
        )
    declared = _first_claim(claims, _DEVICE_COUNT_CLAIMS)
    if not attestation.device_eats:
        failures.append(f"step {record.step_id}: attestation carries no device EATs")
    elif declared is not None and declared != len(attestation.device_eats):
        failures.append(
            f"step {record.step_id}: overall EAT declares {declared!r} devices but "
            f"{len(attestation.device_eats)} device EATs are recorded"
        )
    else:
        passed.append("device_eats_consistent")

    if mode == "offline":
        _check_cached_ocsp(record, config, passed, failures)


def _check_anchor_coverage(
    record: AgDRRecord,
    records: list[AgDRRecord],
    passed: list[str],
    failures: list[str],
) -> None:
    """Check 4: the attestation record sits under an anchored step range.

    Coverage is positional: the attestation record's index in the chain must
    fall between the indices of the anchor's ``from_step_id`` and
    ``to_step_id``. Do not compare step_id strings: UUIDv7 only orders by its
    millisecond timestamp prefix, so records minted within the same
    millisecond have no guaranteed lexicographic order.
    """
    position = {rec.step_id: index for index, rec in enumerate(records)}
    record_index = position.get(record.step_id)
    if record_index is None:
        failures.append(
            f"step {record.step_id}: GPU_ATTESTATION record is not part of the "
            "supplied chain"
        )
        return
    for candidate in records:
        if candidate.kind != StepKind.ANCHOR:
            continue
        step_range = candidate.payload.anchored_step_range
        if step_range is None:
            continue
        low = position.get(step_range.get("from_step_id", ""))
        high = position.get(step_range.get("to_step_id", ""))
        if low is not None and high is not None and low <= record_index <= high:
            passed.append("covered_by_anchored_root")
            return
    failures.append(
        f"step {record.step_id}: GPU_ATTESTATION record is not covered by any "
        "anchored step range; run `air anchor <chain>` so the attestation sits "
        "under an anchored BLAKE3 root"
    )


def _decode_eat(
    attestation: GPUAttestation,
    mode: VerifyMode,
    config: GPUAttestationConfig,
) -> dict[str, object]:
    if mode == "online":
        jwks_url = config.jwks_url if config.jwks_url is not None else _derive_jwks_url(
            attestation.nras_url
        )
        signing_key = pyjwt.PyJWKClient(jwks_url).get_signing_key_from_jwt(
            attestation.detached_eat
        )
        key = signing_key.key
    else:
        if config.cached_signing_cert_path is None:
            raise ValueError(
                "offline attestation verification requires "
                "cached_signing_cert_path (the cached NVIDIA attestation "
                "signing certificate)"
            )
        key = _public_key_from_cert(config.cached_signing_cert_path)
    claims = pyjwt.decode(
        attestation.detached_eat,
        key=key,
        algorithms=_ACCEPTED_EAT_ALGS,
        options={"verify_aud": False},
    )
    if not isinstance(claims, dict):
        raise ValueError("EAT claims must decode to a JSON object")
    return claims


def _check_cached_ocsp(
    record: AgDRRecord,
    config: GPUAttestationConfig,
    passed: list[str],
    failures: list[str],
) -> None:
    """Provisional cached-OCSP check (W1 open decision 2.8).

    When no cached OCSP reference is configured the check is skipped, not
    failed: the cached reference set is optional until the canonical format
    is locked with NVIDIA.
    """
    if config.cached_ocsp_path is None:
        return
    try:
        reference = json.loads(Path(config.cached_ocsp_path).read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        failures.append(f"step {record.step_id}: cached OCSP reference unreadable: {exc}")
        return
    status = reference.get("status") if isinstance(reference, dict) else None
    if status == "good":
        passed.append("cached_ocsp_good")
    else:
        failures.append(
            f"step {record.step_id}: cached OCSP reference status is {status!r}, "
            "expected 'good'"
        )


def _public_key_from_cert(path: Path) -> object:
    certificate = load_pem_x509_certificate(Path(path).read_bytes())
    return certificate.public_key()


def _derive_jwks_url(nras_url: str) -> str:
    from urllib.parse import urlsplit, urlunsplit

    parts = urlsplit(nras_url)
    return urlunsplit((parts.scheme, parts.netloc, "/.well-known/jwks.json", "", ""))


def _first_claim(claims: dict[str, object], names: tuple[str, ...]) -> object:
    for name in names:
        if name in claims:
            return claims[name]
    return None
