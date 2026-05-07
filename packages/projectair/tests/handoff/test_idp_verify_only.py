"""Verify-only Auth0Adapter mode."""
from __future__ import annotations

import pytest

from airsdk.handoff.exceptions import (
    CapabilityTokenInvalidError,
    ConfigurationError,
)
from airsdk.handoff.idp.auth0 import Auth0Adapter

PTID = "7f3a9b2c4d8e1f6a1234567890abcdef"


def test_verify_only_adapter_constructs_without_signing_key(rsa_signer) -> None:
    issuer, _pem, _kid = rsa_signer
    adapter = Auth0Adapter(
        domain="vindicara.us.auth0.com",
        audience="agent:cabinet-coach.v2",
        issuer=issuer,
        jwks_uri=f"{issuer}.well-known/jwks.json",
        verify_only=True,
    )
    assert adapter.handled_issuers() == [issuer]


def test_verify_only_refuses_to_issue(rsa_signer) -> None:
    issuer, _pem, _kid = rsa_signer
    adapter = Auth0Adapter(
        domain="vindicara.us.auth0.com",
        audience="agent:cabinet-coach.v2",
        issuer=issuer,
        jwks_uri=f"{issuer}.well-known/jwks.json",
        verify_only=True,
    )
    with pytest.raises(ConfigurationError, match="verify_only"):
        adapter.issue_capability_token(
            source_agent_id="x", target_agent_id="y",
            target_agent_idp_issuer="https://z/", scopes=[],
            parent_trace_id=PTID, delegation_payload_hash="blake3:" + "0" * 64,
        )


def test_default_rejects_cross_tenant(rsa_signer) -> None:
    """Wave 1 = single-tenant; verify_capability_token defaults to accept_cross_tenant=False."""
    issuer, pem, kid = rsa_signer
    adapter = Auth0Adapter(
        domain="vindicara.us.auth0.com",
        audience="agent:cabinet-coach.v2",
        issuer=issuer,
        jwks_uri=f"{issuer}.well-known/jwks.json",
        signing_key_pem=pem,
        signing_kid=kid,
    )
    tok = adapter.issue_capability_token(
        source_agent_id="agent:cabinet-ea.v3",
        target_agent_id="agent:cabinet-coach.v2",
        target_agent_idp_issuer="https://cabinet-coach.us.auth0.com/",
        scopes=["agent:cabinet-coach:invoke"],
        parent_trace_id=PTID,
        delegation_payload_hash="blake3:" + "0" * 64,
    )
    # Same adapter verifies its own iss claim — passes
    adapter.verify_capability_token(
        raw_jwt=tok.raw_jwt,
        expected_audience="agent:cabinet-coach.v2",
        expected_parent_trace_id=PTID,
    )
    # A second adapter at a different issuer rejects with default
    other = Auth0Adapter(
        domain="other.us.auth0.com",
        audience="agent:cabinet-coach.v2",
        issuer="https://other.us.auth0.com/",
        jwks_uri="https://other.us.auth0.com/.well-known/jwks.json",
        verify_only=True,
    )
    with pytest.raises(CapabilityTokenInvalidError, match="cross-tenant"):
        other.verify_capability_token(
            raw_jwt=tok.raw_jwt,
            expected_audience="agent:cabinet-coach.v2",
            expected_parent_trace_id=PTID,
        )
