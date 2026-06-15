"""Shared fixtures for the W1 GPU attestation suite."""
from __future__ import annotations

import time
from pathlib import Path
from uuid import uuid4

import pytest

from airsdk.attestation import FixtureNRAS, GPUAttestationConfig
from airsdk.recorder import AIRRecorder
from airsdk.types import AuthMethod, DelegationGrant, IntentSpec

NOW = int(time.time())


def make_grant() -> DelegationGrant:
    # delegation_id is unique per session, as in production: the W1 nonce
    # binds to the DELEGATION genesis content hash, so two sessions must
    # never share a byte-identical grant payload.
    return DelegationGrant(
        delegation_id=f"d-attest-{uuid4().hex}",
        agent_id="cc-workload-bot",
        auth_method=AuthMethod.WEBAUTHN,
        authorizer_sub="webauthn:operator-handle",
        authorizer_email="operator@example.org",
        policy_id="attest-demo-v1",
        policy_hash="b3:feedface",
        scope=IntentSpec(goal="run the attested reference workload"),
        granted_at=NOW - 60,
        expires_at=NOW + 3600,
    )


@pytest.fixture
def fixture_nras() -> FixtureNRAS:
    return FixtureNRAS(device_count=2)


@pytest.fixture
def offline_config(tmp_path: Path, fixture_nras: FixtureNRAS) -> GPUAttestationConfig:
    cert = fixture_nras.write_signing_certificate(tmp_path / "nras-cert.pem")
    return GPUAttestationConfig(mode="offline", cached_signing_cert_path=cert)


@pytest.fixture
def attested_recorder(
    tmp_path: Path, fixture_nras: FixtureNRAS, offline_config: GPUAttestationConfig
) -> AIRRecorder:
    return AIRRecorder(
        tmp_path / "chain.jsonl",
        delegation=make_grant(),
        attestation=offline_config,
        attestation_provider=fixture_nras,
    )
