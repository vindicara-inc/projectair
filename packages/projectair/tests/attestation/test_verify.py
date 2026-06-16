"""Verification flow: per-root checks, replay defense, legacy chains."""
from __future__ import annotations

from pathlib import Path

import jwt as pyjwt
from cryptography.hazmat.primitives.asymmetric import ec
from tests.attestation.conftest import make_grant

from airsdk.agdr import Signer, load_chain, verify_chain
from airsdk.anchoring import AnchoringOrchestrator
from airsdk.attestation import (
    FixtureNRAS,
    GPUAttestationConfig,
    verify_attestation,
)
from airsdk.recorder import AIRRecorder
from airsdk.types import AgDRPayload, AgDRRecord, StepKind, VerificationStatus


def _chain_of(recorder: AIRRecorder) -> list[AgDRRecord]:
    return load_chain(recorder.log_path)


def _anchor(recorder: AIRRecorder) -> None:
    orchestrator = AnchoringOrchestrator(
        signer=recorder.signer, transports=recorder.transports
    )
    orchestrator.hydrate_from_chain(_chain_of(recorder))
    orchestrator.emit_anchor_now()


def test_offline_verify_passes_end_to_end(
    attested_recorder: AIRRecorder, offline_config: GPUAttestationConfig
) -> None:
    attested_recorder.tool_start(tool_name="run_workload", tool_args={})
    attested_recorder.tool_end(tool_output="done")
    _anchor(attested_recorder)
    records = _chain_of(attested_recorder)

    assert verify_chain(records).status == VerificationStatus.OK
    result = verify_attestation(records, mode="offline", config=offline_config)
    assert result.failures == []
    assert result.ok
    assert result.records_checked == 1
    assert "nonce_binds_to_genesis" in result.checks_passed
    assert "eat_signature_offline" in result.checks_passed
    assert "eat_nonce_matches_record" in result.checks_passed
    assert "rim_matched" in result.checks_passed
    assert "device_eats_consistent" in result.checks_passed
    assert "covered_by_anchored_root" in result.checks_passed


def test_legacy_chain_without_attestation_stays_green(tmp_path: Path) -> None:
    recorder = AIRRecorder(tmp_path / "legacy.jsonl", delegation=make_grant())
    recorder.tool_start(tool_name="x", tool_args={})
    records = _chain_of(recorder)
    result = verify_attestation(records, mode="offline")
    assert result.ok
    assert result.records_checked == 0


def test_replayed_nonce_fails_closed(
    tmp_path: Path, fixture_nras: FixtureNRAS, offline_config: GPUAttestationConfig
) -> None:
    """An EAT minted for one session must not verify on another chain."""
    first = AIRRecorder(
        tmp_path / "first.jsonl",
        delegation=make_grant(),
        attestation=offline_config,
        attestation_provider=fixture_nras,
    )
    stolen = _chain_of(first)[2].payload.attestation
    assert stolen is not None

    second = AIRRecorder(tmp_path / "second.jsonl", delegation=make_grant())
    signer = Signer.from_env()
    replayed_chain = _chain_of(second)
    signer._prev_hash = replayed_chain[-1].content_hash
    replay = signer.sign(
        kind=StepKind.GPU_ATTESTATION,
        payload=AgDRPayload(attestation=stolen),
    )
    result = verify_attestation(
        [*replayed_chain, replay], mode="offline", config=offline_config
    )
    assert not result.ok
    assert any("replay defense" in failure for failure in result.failures)


def test_forged_eat_signature_fails(
    attested_recorder: AIRRecorder, offline_config: GPUAttestationConfig
) -> None:
    """An EAT signed by any key other than the cached cert's must fail."""
    _anchor(attested_recorder)
    records = _chain_of(attested_recorder)
    attestation = records[2].payload.attestation
    assert attestation is not None
    rogue_key = ec.generate_private_key(ec.SECP384R1())
    claims = pyjwt.decode(attestation.detached_eat, options={"verify_signature": False})
    forged = pyjwt.encode(claims, rogue_key, algorithm="ES384")
    tampered = attestation.model_copy(update={"detached_eat": forged})
    records[2].payload.attestation = tampered

    result = verify_attestation(records, mode="offline", config=offline_config)
    assert not result.ok
    assert any("signature verification failed" in f for f in result.failures)


def test_rim_mismatch_fails(tmp_path: Path) -> None:
    fixture = FixtureNRAS(rim_matched=False)
    cert = fixture.write_signing_certificate(tmp_path / "cert.pem")
    config = GPUAttestationConfig(mode="offline", cached_signing_cert_path=cert)
    recorder = AIRRecorder(
        tmp_path / "chain.jsonl",
        delegation=make_grant(),
        attestation=config,
        attestation_provider=fixture,
    )
    result = verify_attestation(_chain_of(recorder), mode="offline", config=config)
    assert not result.ok
    assert any("Reference Integrity Manifest" in f for f in result.failures)


def test_unanchored_attestation_fails_coverage(
    attested_recorder: AIRRecorder, offline_config: GPUAttestationConfig
) -> None:
    records = _chain_of(attested_recorder)
    result = verify_attestation(records, mode="offline", config=offline_config)
    assert not result.ok
    assert any("anchored step range" in f for f in result.failures)


def test_offline_mode_requires_cached_cert(attested_recorder: AIRRecorder) -> None:
    records = _chain_of(attested_recorder)
    result = verify_attestation(
        records, mode="offline", config=GPUAttestationConfig(mode="offline")
    )
    assert not result.ok
    assert any("cached_signing_cert_path" in f for f in result.failures)


def test_cached_ocsp_reference(
    tmp_path: Path, fixture_nras: FixtureNRAS, attested_recorder: AIRRecorder
) -> None:
    _anchor(attested_recorder)
    records = _chain_of(attested_recorder)
    cert = fixture_nras.write_signing_certificate(tmp_path / "c.pem")

    good = tmp_path / "ocsp-good.json"
    good.write_text('{"status": "good"}', encoding="utf-8")
    config = GPUAttestationConfig(
        mode="offline", cached_signing_cert_path=cert, cached_ocsp_path=good
    )
    result = verify_attestation(records, mode="offline", config=config)
    assert result.ok
    assert "cached_ocsp_good" in result.checks_passed

    revoked = tmp_path / "ocsp-revoked.json"
    revoked.write_text('{"status": "revoked"}', encoding="utf-8")
    config = GPUAttestationConfig(
        mode="offline", cached_signing_cert_path=cert, cached_ocsp_path=revoked
    )
    result = verify_attestation(records, mode="offline", config=config)
    assert not result.ok


def test_fixture_tokens_are_marked_simulated(attested_recorder: AIRRecorder) -> None:
    attestation = _chain_of(attested_recorder)[2].payload.attestation
    assert attestation is not None
    claims = pyjwt.decode(attestation.detached_eat, options={"verify_signature": False})
    assert claims["x-nvidia-simulated"] is True
