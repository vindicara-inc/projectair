"""Auth0 flow helper tests: URL builder, PKCE, device flow polling."""
from __future__ import annotations

import base64
import hashlib
import json
import urllib.error
import urllib.parse
from unittest.mock import MagicMock, patch

import pytest

from airsdk.containment.auth0_flows import (
    Auth0DeviceFlowError,
    Auth0Tenant,
    DeviceAuthorization,
    build_authorize_url,
    make_pkce_pair,
    poll_device_token,
    start_device_flow,
)


def _tenant(client_id: str | None = "test-client") -> Auth0Tenant:
    return Auth0Tenant(
        domain="tenant.us.auth0.com",
        audience="https://api.vindicara.io",
        client_id=client_id,
    )


def test_tenant_derived_urls_are_well_formed() -> None:
    t = _tenant()
    assert t.issuer == "https://tenant.us.auth0.com/"
    assert t.authorize_url == "https://tenant.us.auth0.com/authorize"
    assert t.token_url == "https://tenant.us.auth0.com/oauth/token"  # noqa: S105 - URL, not credential
    assert t.device_code_url == "https://tenant.us.auth0.com/oauth/device/code"
    assert t.jwks_uri == "https://tenant.us.auth0.com/.well-known/jwks.json"


def test_authorize_url_contains_required_params() -> None:
    url = build_authorize_url(_tenant(), "challenge-abc", "https://app/callback")
    parsed = urllib.parse.urlparse(url)
    qs = urllib.parse.parse_qs(parsed.query)
    assert parsed.netloc == "tenant.us.auth0.com"
    assert parsed.path == "/authorize"
    assert qs["client_id"] == ["test-client"]
    assert qs["audience"] == ["https://api.vindicara.io"]
    assert qs["response_type"] == ["code"]
    assert qs["redirect_uri"] == ["https://app/callback"]
    assert qs["state"] == ["challenge-abc"]
    assert qs["scope"] == ["openid email profile"]


def test_authorize_url_includes_pkce_when_supplied() -> None:
    url = build_authorize_url(
        _tenant(),
        "challenge-abc",
        "https://app/callback",
        code_challenge="abc123",
    )
    qs = urllib.parse.parse_qs(urllib.parse.urlparse(url).query)
    assert qs["code_challenge"] == ["abc123"]
    assert qs["code_challenge_method"] == ["S256"]


def test_authorize_url_omits_pkce_when_not_supplied() -> None:
    url = build_authorize_url(_tenant(), "challenge-abc", "https://app/callback")
    qs = urllib.parse.parse_qs(urllib.parse.urlparse(url).query)
    assert "code_challenge" not in qs
    assert "code_challenge_method" not in qs


def test_authorize_url_rejects_tenant_without_client_id() -> None:
    with pytest.raises(ValueError, match="client_id"):
        build_authorize_url(
            _tenant(client_id=None),
            "challenge-abc",
            "https://app/callback",
        )


def test_pkce_pair_round_trips_correctly() -> None:
    """The challenge must be base64url(sha256(verifier)). RFC 7636."""
    verifier, challenge = make_pkce_pair()
    expected = base64.urlsafe_b64encode(
        hashlib.sha256(verifier.encode("ascii")).digest(),
    ).rstrip(b"=").decode("ascii")
    assert challenge == expected
    assert len(verifier) >= 43  # RFC minimum
    assert len(verifier) <= 128  # RFC max


def test_pkce_pairs_are_distinct() -> None:
    pairs = {make_pkce_pair() for _ in range(20)}
    assert len(pairs) == 20  # entropy check


def _device_response_mock(payload: dict[str, object]) -> MagicMock:
    body = json.dumps(payload).encode("utf-8")
    mock = MagicMock()
    mock.read.return_value = body
    mock.__enter__ = MagicMock(return_value=mock)
    mock.__exit__ = MagicMock(return_value=False)
    return mock


def test_start_device_flow_parses_response() -> None:
    payload = {
        "device_code": "dc-123",
        "user_code": "ABCD-EFGH",
        "verification_uri": "https://tenant.us.auth0.com/activate",
        "verification_uri_complete": "https://tenant.us.auth0.com/activate?user_code=ABCD-EFGH",
        "expires_in": 900,
        "interval": 5,
    }
    with patch(
        "airsdk.containment.auth0_flows.urllib.request.urlopen",
        return_value=_device_response_mock(payload),
    ):
        auth = start_device_flow(_tenant())
    assert isinstance(auth, DeviceAuthorization)
    assert auth.device_code == "dc-123"
    assert auth.user_code == "ABCD-EFGH"
    assert auth.verification_uri == "https://tenant.us.auth0.com/activate"
    assert auth.verification_uri_complete.endswith("user_code=ABCD-EFGH")
    assert auth.expires_in == 900
    assert auth.interval == 5


def test_start_device_flow_rejects_missing_client_id() -> None:
    with pytest.raises(ValueError, match="client_id"):
        start_device_flow(_tenant(client_id=None))


def test_poll_device_token_returns_access_token_on_success() -> None:
    success = _device_response_mock(
        {"access_token": "ey.fake.jwt", "id_token": "ey.id.jwt"},
    )
    with patch(
        "airsdk.containment.auth0_flows.urllib.request.urlopen",
        return_value=success,
    ):
        token = poll_device_token(_tenant(), "dc-123", interval=1, max_poll_seconds=5.0)
    assert token == "ey.fake.jwt"  # noqa: S105 - JWT, not a password


def test_poll_device_token_polls_through_authorization_pending() -> None:
    """Auth0 returns 403 + ``authorization_pending`` until the user
    completes the flow. The poller must keep going."""
    pending_err = urllib.error.HTTPError(
        url="https://x", code=403, msg="forbidden", hdrs=None,  # type: ignore[arg-type]
        fp=None,
    )
    pending_err.read = MagicMock(  # type: ignore[method-assign]
        return_value=json.dumps({"error": "authorization_pending"}).encode("utf-8"),
    )
    success = _device_response_mock({"access_token": "final.token"})

    sequence: list[object] = [pending_err, pending_err, success]

    def side_effect(*_args: object, **_kwargs: object) -> object:
        item = sequence.pop(0)
        if isinstance(item, urllib.error.HTTPError):
            raise item
        return item

    with (
        patch("airsdk.containment.auth0_flows.urllib.request.urlopen", side_effect=side_effect),
        patch("airsdk.containment.auth0_flows.time.sleep"),
    ):
        token = poll_device_token(_tenant(), "dc-123", interval=1, max_poll_seconds=10.0)
    assert token == "final.token"  # noqa: S105 - JWT, not a password
    assert not sequence  # all three responses consumed


def test_poll_device_token_raises_on_access_denied() -> None:
    denied = urllib.error.HTTPError(
        url="https://x", code=403, msg="forbidden", hdrs=None,  # type: ignore[arg-type]
        fp=None,
    )
    denied.read = MagicMock(  # type: ignore[method-assign]
        return_value=json.dumps({"error": "access_denied"}).encode("utf-8"),
    )
    with patch(
        "airsdk.containment.auth0_flows.urllib.request.urlopen",
        side_effect=denied,
    ), pytest.raises(Auth0DeviceFlowError, match="denied"):
        poll_device_token(_tenant(), "dc-123", interval=1, max_poll_seconds=5.0)


def test_poll_device_token_raises_on_expired_token() -> None:
    expired = urllib.error.HTTPError(
        url="https://x", code=403, msg="forbidden", hdrs=None,  # type: ignore[arg-type]
        fp=None,
    )
    expired.read = MagicMock(  # type: ignore[method-assign]
        return_value=json.dumps({"error": "expired_token"}).encode("utf-8"),
    )
    with patch(
        "airsdk.containment.auth0_flows.urllib.request.urlopen",
        side_effect=expired,
    ), pytest.raises(Auth0DeviceFlowError, match="expired"):
        poll_device_token(_tenant(), "dc-123", interval=1, max_poll_seconds=5.0)


def test_poll_device_token_times_out_when_user_never_acts() -> None:
    """If the polling deadline expires before the user finishes,
    raise rather than block forever."""
    pending = urllib.error.HTTPError(
        url="https://x", code=403, msg="forbidden", hdrs=None,  # type: ignore[arg-type]
        fp=None,
    )
    pending.read = MagicMock(  # type: ignore[method-assign]
        return_value=json.dumps({"error": "authorization_pending"}).encode("utf-8"),
    )
    with (
        patch("airsdk.containment.auth0_flows.urllib.request.urlopen", side_effect=pending),
        patch("airsdk.containment.auth0_flows.time.sleep"),pytest.raises(Auth0DeviceFlowError, match="timed out")
    ):
        poll_device_token(_tenant(), "dc-123", interval=1, max_poll_seconds=0.05)
