"""Auth0 reference adapter + AdapterRouter + placeholder tests."""
from __future__ import annotations

import time

import jwt
import pytest

from airsdk.handoff.exceptions import (
    CapabilityTokenInvalidError,
    ConfigurationError,
    CustomClaimMissingError,
    IdPNotImplementedError,
    UnregisteredIssuerError,
)
from airsdk.handoff.idp.auth0 import MAX_TTL_SECONDS, Auth0Adapter
from airsdk.handoff.idp.base import REQUIRED_AIR_CLAIMS, AdapterRouter
from airsdk.handoff.idp.entra import EntraAdapter
from airsdk.handoff.idp.okta import OktaAdapter
from airsdk.handoff.idp.spiffe import SpiffeAdapter

PTID = "7f3a9b2c4d8e1f6a1234567890abcdef"


def _issue(adapter: Auth0Adapter):
    return adapter.issue_capability_token(
        source_agent_id="agent:cabinet-ea.v3",
        target_agent_id="agent:cabinet-coach.v2",
        target_agent_idp_issuer="https://cabinet-coach.us.auth0.com/",
        scopes=["agent:cabinet-coach:invoke"],
        parent_trace_id=PTID,
        delegation_payload_hash="blake3:" + "0" * 64,
    )


def test_issue_then_verify_roundtrip(adapter: Auth0Adapter) -> None:
    tok = _issue(adapter)
    assert tok.air_ptid == PTID
    assert all(c in tok.claims for c in REQUIRED_AIR_CLAIMS)
    again = adapter.verify_capability_token(
        raw_jwt=tok.raw_jwt,
        expected_audience="agent:cabinet-coach.v2",
        expected_parent_trace_id=PTID,
    )
    assert again.jti == tok.jti


def test_wrong_audience_fails(adapter: Auth0Adapter) -> None:
    tok = _issue(adapter)
    with pytest.raises(CapabilityTokenInvalidError):
        adapter.verify_capability_token(
            raw_jwt=tok.raw_jwt,
            expected_audience="agent:other.v1",
            expected_parent_trace_id=PTID,
        )


def test_air_ptid_mismatch_fails(adapter: Auth0Adapter) -> None:
    tok = _issue(adapter)
    with pytest.raises(CapabilityTokenInvalidError, match="air_ptid"):
        adapter.verify_capability_token(
            raw_jwt=tok.raw_jwt,
            expected_audience="agent:cabinet-coach.v2",
            expected_parent_trace_id="a" * 32,
        )


def test_missing_air_claim_raises_custom_claim_missing(rsa_signer) -> None:
    issuer, pem, kid = rsa_signer
    adapter = Auth0Adapter(
        domain="vindicara.us.auth0.com",
        audience="agent:cabinet-coach.v2",
        issuer=issuer,
        jwks_uri=f"{issuer}.well-known/jwks.json",
        signing_key_pem=pem,
        signing_kid=kid,
    )
    bad = jwt.encode(
        {
            "iss": issuer,
            "sub": "agent:cabinet-ea.v3",
            "aud": "agent:cabinet-coach.v2",
            "exp": int(time.time()) + 60,
            "iat": int(time.time()),
            "jti": "tok_no_air",
        },
        pem,
        algorithm="RS256",
        headers={"kid": kid},
    )
    with pytest.raises(CustomClaimMissingError, match="air_ptid"):
        adapter.verify_capability_token(
            raw_jwt=bad,
            expected_audience="agent:cabinet-coach.v2",
            expected_parent_trace_id=PTID,
        )


def test_router_unknown_issuer_rejected(adapter: Auth0Adapter) -> None:
    router = AdapterRouter()
    router.register(adapter)
    with pytest.raises(UnregisteredIssuerError):
        router.route("https://attacker.example.com/")


def test_router_duplicate_registration_rejected(adapter: Auth0Adapter) -> None:
    router = AdapterRouter()
    router.register(adapter)
    with pytest.raises(ConfigurationError):
        router.register(adapter)


def test_max_ttl_enforced(adapter: Auth0Adapter) -> None:
    with pytest.raises(ConfigurationError):
        adapter.issue_capability_token(
            source_agent_id="x",
            target_agent_id="y",
            target_agent_idp_issuer="https://z/",
            scopes=[],
            parent_trace_id=PTID,
            delegation_payload_hash="blake3:" + "0" * 64,
            ttl_seconds=MAX_TTL_SECONDS + 1,
        )


@pytest.mark.parametrize("cls", [OktaAdapter, EntraAdapter, SpiffeAdapter])
def test_placeholder_adapters_not_implemented(cls) -> None:
    with pytest.raises(IdPNotImplementedError):
        cls()
