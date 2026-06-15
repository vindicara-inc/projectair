"""NRAS client: response parsing and failure modes."""
from __future__ import annotations

import urllib.error

import pytest

from airsdk.attestation import (
    EvidenceUnavailableError,
    FixtureNRAS,
    GPUAttestationConfig,
    NRASClient,
    NRASResponseError,
    NRASUnreachableError,
    attest_session,
    parse_nras_response,
)
from airsdk.attestation.types import DeviceEvidence, EvidenceBundle

GENESIS = "ab" * 32


def _bundle(nonce: str = "00" * 32) -> EvidenceBundle:
    return EvidenceBundle(
        gpu_arch="hopper",
        nonce=nonce,
        devices=[DeviceEvidence(device_id="GPU-0", evidence_b64="ZXZpZGVuY2U=")],
    )


def test_parse_object_form() -> None:
    result = parse_nras_response(
        {
            "detached_eat": "overall.jwt.token",
            "device_eats": ["dev0.jwt", "dev1.jwt"],
            "claims_version": "3.0",
            "rim_matched": True,
        }
    )
    assert result.detached_eat == "overall.jwt.token"
    assert result.device_eats == ["dev0.jwt", "dev1.jwt"]
    assert result.claims_version == "3.0"
    assert result.rim_matched is True


def test_parse_array_form_uses_real_jwt_claims() -> None:
    fixture = FixtureNRAS(device_count=2)
    issued = fixture.attest(nonce="11" * 32, gpu_arch="blackwell")
    raw = [
        ["JWT", issued.detached_eat],
        {"GPU-0": issued.device_eats[0], "GPU-1": issued.device_eats[1]},
    ]
    result = parse_nras_response(raw)
    assert result.detached_eat == issued.detached_eat
    assert len(result.device_eats) == 2
    assert result.rim_matched is True
    assert result.claims_version == issued.claims_version


@pytest.mark.parametrize(
    "raw",
    [
        "just a string",
        {"detached_eat": 5, "device_eats": []},
        {"device_eats": ["x"]},
        [],
        [["NOT-JWT", "x"], {}],
        [["JWT", "header.payload.sig"], "not a dict"],
    ],
)
def test_parse_rejects_malformed_responses(raw: object) -> None:
    with pytest.raises(NRASResponseError):
        parse_nras_response(raw)  # type: ignore[arg-type]


def test_client_wraps_network_failure() -> None:
    def failing_post(url: str, body: dict, timeout: float) -> dict:  # type: ignore[type-arg]
        raise urllib.error.URLError("connection refused")

    client = NRASClient(GPUAttestationConfig(), post_json=failing_post)
    with pytest.raises(NRASUnreachableError):
        client.attest_evidence(_bundle())


def test_client_posts_evidence_and_parses(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, object] = {}

    def fake_post(url: str, body: dict, timeout: float) -> dict:  # type: ignore[type-arg]
        captured["url"] = url
        captured["body"] = body
        return {
            "detached_eat": "overall.jwt",
            "device_eats": ["d0.jwt"],
            "claims_version": "3.0",
            "rim_matched": True,
        }

    client = NRASClient(GPUAttestationConfig(), post_json=fake_post)
    result = client.attest_evidence(_bundle(nonce="aa" * 32))
    assert result.rim_matched is True
    body = captured["body"]
    assert isinstance(body, dict)
    assert body["nonce"] == "aa" * 32
    assert body["arch"] == "HOPPER"
    assert isinstance(body["evidence_list"], list)


def test_default_transport_rejects_non_https_endpoints() -> None:
    from airsdk.attestation.nras import _post_json_urllib

    with pytest.raises(NRASUnreachableError, match="must be https"):
        _post_json_urllib("http://nras.example/v3/attest/gpu", {}, 1.0)
    with pytest.raises(NRASUnreachableError, match="must be https"):
        _post_json_urllib("fixture://nras.simulated.local/v3/attest/gpu", {}, 1.0)


def test_live_evidence_collection_unavailable_off_cc_hardware() -> None:
    client = NRASClient(GPUAttestationConfig())
    with pytest.raises(EvidenceUnavailableError):
        client.attest(nonce="00" * 32, gpu_arch="hopper")


def test_attest_session_builds_chain_bound_capsule_fields() -> None:
    fixture = FixtureNRAS()
    config = GPUAttestationConfig(mode="offline")
    attestation = attest_session(GENESIS, config, provider=fixture)
    assert attestation.nras_url == fixture.nras_url
    assert attestation.gpu_arch == "hopper"
    assert attestation.rim_matched is True
    assert attestation.verification_hint == "cached_rim_ocsp"
    assert len(attestation.device_eats) == 1
    assert attestation.measured_at.endswith("Z")
