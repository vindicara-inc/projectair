"""Live Auth0 integration tests (env-gated; do not run in CI by default).

Skipped unless ``AIR_AUTH0_DOMAIN``, ``AIR_AUTH0_CLIENT_ID``,
``AIR_AUTH0_CLIENT_SECRET``, and ``AIR_AUTH0_AUDIENCE`` are all present in
the environment. Run with ``-m integration`` (or remove the marker filter)
once those are set.

These tests confirm the Auth0 Action attached to the M2M / Client
Credentials Exchange trigger is correctly injecting the four ``air_*``
custom claims (Section 7.3.1). Without the Action deployed, every test
in this module fails with :class:`CustomClaimMissingError`, pointing
the operator at the exact Action JS to deploy.
"""
from __future__ import annotations

import os

import pytest

from airsdk.handoff.exceptions import CustomClaimMissingError
from airsdk.handoff.idp.auth0 import Auth0Adapter
from airsdk.handoff.idp.base import REQUIRED_AIR_CLAIMS

pytestmark = pytest.mark.integration


def _env_or_skip() -> dict[str, str]:
    needed = (
        "AIR_AUTH0_DOMAIN",
        "AIR_AUTH0_CLIENT_ID",
        "AIR_AUTH0_CLIENT_SECRET",
        "AIR_AUTH0_AUDIENCE",
    )
    missing = [k for k in needed if not os.environ.get(k)]
    if missing:
        pytest.skip(f"live Auth0 env vars not set: {missing}")
    return {k: os.environ[k] for k in needed}


def _adapter() -> Auth0Adapter:
    env = _env_or_skip()
    return Auth0Adapter(
        domain=env["AIR_AUTH0_DOMAIN"],
        audience=env["AIR_AUTH0_AUDIENCE"],
        client_id=env["AIR_AUTH0_CLIENT_ID"],
        client_secret=env["AIR_AUTH0_CLIENT_SECRET"],
    )


PTID = "7f3a9b2c4d8e1f6a1234567890abcdef"


def test_auth0_action_injects_custom_claims_live() -> None:
    """End-to-end live: mint a token via /oauth/token and confirm the four air_* claims land.

    If this fails with CustomClaimMissingError, the Auth0 Action is not
    deployed correctly. Reference Action code is in spec Section 7.3.1.
    """
    adapter = _adapter()
    audience = os.environ["AIR_AUTH0_AUDIENCE"]
    try:
        token = adapter.issue_capability_token(
            source_agent_id="agent:cabinet-ea.v3",
            target_agent_id=audience,
            target_agent_idp_issuer=adapter.issuer,
            scopes=["agent:cabinet-coach:invoke"],
            parent_trace_id=PTID,
            delegation_payload_hash="blake3:" + "0" * 64,
        )
    except CustomClaimMissingError as e:
        pytest.fail(
            f"Auth0 Action is missing or not deployed. "
            f"See spec Section 7.3.1 for the Action code. Original error: {e}"
        )
    assert token.air_ptid == PTID
    for claim in REQUIRED_AIR_CLAIMS:
        assert claim in token.claims, f"Auth0 Action did not inject {claim}"


def test_auth0_jwks_round_trip_live() -> None:
    """Confirm the Auth0 tenant's JWKS is reachable and verifies its own tokens."""
    adapter = _adapter()
    audience = os.environ["AIR_AUTH0_AUDIENCE"]
    token = adapter.issue_capability_token(
        source_agent_id="agent:cabinet-ea.v3",
        target_agent_id=audience,
        target_agent_idp_issuer=adapter.issuer,
        scopes=["agent:cabinet-coach:invoke"],
        parent_trace_id=PTID,
        delegation_payload_hash="blake3:" + "0" * 64,
    )
    re = adapter.verify_capability_token(
        raw_jwt=token.raw_jwt,
        expected_audience=audience,
        expected_parent_trace_id=PTID,
    )
    assert re.jti == token.jti
