"""ML-DSA-65 (FIPS 204) signing tests and mixed-algorithm chain verification."""
from __future__ import annotations

from pathlib import Path

import pytest

from airsdk.agdr import Signer, export_private_key_pem, load_chain, verify_chain, verify_record
from airsdk.types import AgDRPayload, SigningAlgorithm, StepKind, VerificationStatus


@pytest.fixture
def mldsa_signer() -> Signer:
    return Signer.generate(SigningAlgorithm.ML_DSA_65)


@pytest.fixture
def ed25519_signer() -> Signer:
    return Signer.generate(SigningAlgorithm.ED25519)


class TestMLDSA65Signing:
    def test_generate_mldsa_signer(self, mldsa_signer: Signer) -> None:
        assert mldsa_signer.algorithm == SigningAlgorithm.ML_DSA_65

    def test_sign_produces_valid_record(self, mldsa_signer: Signer) -> None:
        record = mldsa_signer.sign(StepKind.LLM_START, AgDRPayload(prompt="hello"))
        assert record.signature_algorithm == SigningAlgorithm.ML_DSA_65
        assert record.kind == StepKind.LLM_START
        ok, reason = verify_record(record)
        assert ok, reason

    def test_chain_links_correctly(self, mldsa_signer: Signer) -> None:
        first = mldsa_signer.sign(StepKind.LLM_START, AgDRPayload(prompt="hello"))
        second = mldsa_signer.sign(StepKind.LLM_END, AgDRPayload(response="hi"))
        assert second.prev_hash == first.content_hash
        result = verify_chain([first, second])
        assert result.status == VerificationStatus.OK
        assert result.records_verified == 2

    def test_detects_payload_tamper(self, mldsa_signer: Signer) -> None:
        first = mldsa_signer.sign(StepKind.LLM_START, AgDRPayload(prompt="hello"))
        second = mldsa_signer.sign(StepKind.LLM_END, AgDRPayload(response="hi"))
        tampered = second.model_copy(update={"payload": AgDRPayload(response="goodbye")})
        result = verify_chain([first, tampered])
        assert result.status == VerificationStatus.TAMPERED

    def test_signature_is_larger_than_ed25519(self, mldsa_signer: Signer, ed25519_signer: Signer) -> None:
        ml_rec = mldsa_signer.sign(StepKind.LLM_START, AgDRPayload(prompt="x"))
        ed_rec = ed25519_signer.sign(StepKind.LLM_START, AgDRPayload(prompt="x"))
        assert len(ml_rec.signature) > len(ed_rec.signature)
        assert len(ml_rec.signer_key) > len(ed_rec.signer_key)

    def test_public_key_hex_is_3904_chars(self, mldsa_signer: Signer) -> None:
        assert len(mldsa_signer.public_key_hex) == 3904

    def test_export_private_key_pem(self, mldsa_signer: Signer) -> None:
        pem = export_private_key_pem(mldsa_signer)
        assert pem.startswith(b"-----BEGIN PRIVATE KEY-----")

    def test_load_chain_roundtrip(self, tmp_path: Path, mldsa_signer: Signer) -> None:
        first = mldsa_signer.sign(StepKind.LLM_START, AgDRPayload(prompt="hello"))
        second = mldsa_signer.sign(StepKind.LLM_END, AgDRPayload(response="hi"))
        log = tmp_path / "ml-dsa-trace.log"
        log.write_text(
            first.model_dump_json(exclude_none=True) + "\n"
            + second.model_dump_json(exclude_none=True) + "\n"
        )
        loaded = load_chain(log)
        assert len(loaded) == 2
        assert loaded[0].signature_algorithm == SigningAlgorithm.ML_DSA_65
        assert verify_chain(loaded).status == VerificationStatus.OK


class TestMixedAlgorithmChain:
    def test_ed25519_then_mldsa_verifies(self) -> None:
        """Two independent signers, different algorithms, valid chain linking."""
        ed_signer = Signer.generate(SigningAlgorithm.ED25519)
        first = ed_signer.sign(StepKind.LLM_START, AgDRPayload(prompt="hello"))

        ml_signer = Signer.generate(SigningAlgorithm.ML_DSA_65)
        ml_signer._prev_hash = first.content_hash
        second = ml_signer.sign(StepKind.LLM_END, AgDRPayload(response="hi"))

        assert first.signature_algorithm == SigningAlgorithm.ED25519
        assert second.signature_algorithm == SigningAlgorithm.ML_DSA_65
        result = verify_chain([first, second])
        assert result.status == VerificationStatus.OK
        assert result.records_verified == 2

    def test_mldsa_then_ed25519_verifies(self) -> None:
        ml_signer = Signer.generate(SigningAlgorithm.ML_DSA_65)
        first = ml_signer.sign(StepKind.LLM_START, AgDRPayload(prompt="hello"))

        ed_signer = Signer.generate(SigningAlgorithm.ED25519)
        ed_signer._prev_hash = first.content_hash
        second = ed_signer.sign(StepKind.LLM_END, AgDRPayload(response="hi"))

        result = verify_chain([first, second])
        assert result.status == VerificationStatus.OK


class TestBackwardCompatibility:
    def test_record_without_signature_algorithm_defaults_to_ed25519(self) -> None:
        """v0.4 records omit signature_algorithm; default is ed25519."""
        signer = Signer.generate()
        record = signer.sign(StepKind.LLM_START, AgDRPayload(prompt="old"))
        raw = record.model_dump(exclude_none=True)
        del raw["signature_algorithm"]
        from airsdk.types import AgDRRecord
        loaded = AgDRRecord.model_validate(raw)
        assert loaded.signature_algorithm == "ed25519"
        ok, reason = verify_record(loaded)
        assert ok, reason

    def test_algorithm_property_on_signer(self) -> None:
        ed = Signer.generate(SigningAlgorithm.ED25519)
        ml = Signer.generate(SigningAlgorithm.ML_DSA_65)
        assert ed.algorithm == SigningAlgorithm.ED25519
        assert ml.algorithm == SigningAlgorithm.ML_DSA_65

    def test_from_env_with_mldsa_algorithm(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Hex seed + algorithm=ML_DSA_65 loads the right key type."""
        seed_hex = "a" * 64
        monkeypatch.setenv("TEST_KEY", seed_hex)
        signer = Signer.from_env("TEST_KEY", algorithm=SigningAlgorithm.ML_DSA_65)
        assert signer.algorithm == SigningAlgorithm.ML_DSA_65

    def test_from_env_pem_autodetects_mldsa(self) -> None:
        """PEM-encoded ML-DSA-65 key auto-detects without algorithm hint."""
        from cryptography.hazmat.primitives.asymmetric.mldsa import MLDSA65PrivateKey
        from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat

        key = MLDSA65PrivateKey.generate()
        pem = key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()).decode()
        import os
        os.environ["_TEST_MLDSA_PEM"] = pem
        try:
            signer = Signer.from_env("_TEST_MLDSA_PEM")
            assert signer.algorithm == SigningAlgorithm.ML_DSA_65
        finally:
            del os.environ["_TEST_MLDSA_PEM"]


class TestRecorderIntegration:
    def test_recorder_with_mldsa(self, tmp_path: Path) -> None:
        from airsdk.recorder import AIRRecorder
        rec = AIRRecorder(
            tmp_path / "chain.jsonl",
            signing_algorithm=SigningAlgorithm.ML_DSA_65,
        )
        record = rec.llm_start(prompt="hello")
        assert record.signature_algorithm == SigningAlgorithm.ML_DSA_65
        ok, reason = verify_record(record)
        assert ok, reason
