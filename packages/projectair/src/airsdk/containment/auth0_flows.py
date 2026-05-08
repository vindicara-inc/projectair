"""Auth0 OAuth flow helpers for step-up approval.

The verifier in :mod:`airsdk.containment.auth0` validates a token after
the human has authenticated. This module is the flow side: the helpers
that get the human authenticated in the first place.

Two flows are supported, matching the two operational realities:

- **Browser flow** (Authorization Code with PKCE). For interactive
  consoles where the operator can click a link and log in via Auth0
  Universal Login. ``build_authorize_url`` generates the URL.
- **Device authorization** (RFC 8628). For headless agents and CLI
  tools where the operator authenticates on a separate device.
  ``start_device_flow`` issues the user code; ``poll_device_token``
  blocks until the user completes the flow on their phone.

The challenge_id raised by ``StepUpRequiredError`` is carried as the
OAuth ``state`` parameter (browser) or out-of-band (device), so the
returning token can be matched back to the originally-halted action.
"""
from __future__ import annotations

import json
import secrets
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any, Final

_DEFAULT_HTTP_TIMEOUT: Final[float] = 10.0
_DEFAULT_DEVICE_POLL_TIMEOUT: Final[float] = 300.0


@dataclass(frozen=True)
class Auth0Tenant:
    """Config bundle for an Auth0 tenant.

    Pass this to the flow helpers and to :class:`Auth0Verifier`. The
    tenant's domain (without scheme) is the only required field for the
    verifier; ``client_id`` is required for browser and device flows.

    ``audience`` is the API identifier the access token will be minted
    for; the verifier and the recorder must agree on this value, so it
    lives on the tenant config rather than being passed at every call.
    """

    domain: str
    audience: str
    client_id: str | None = None
    scope: str = "openid email profile"

    @property
    def issuer(self) -> str:
        return f"https://{self.domain}/"

    @property
    def authorize_url(self) -> str:
        return f"https://{self.domain}/authorize"

    @property
    def token_url(self) -> str:
        return f"https://{self.domain}/oauth/token"

    @property
    def device_code_url(self) -> str:
        return f"https://{self.domain}/oauth/device/code"

    @property
    def jwks_uri(self) -> str:
        return f"https://{self.domain}/.well-known/jwks.json"


def build_authorize_url(
    tenant: Auth0Tenant,
    challenge_id: str,
    redirect_uri: str,
    *,
    code_challenge: str | None = None,
    additional_params: dict[str, str] | None = None,
) -> str:
    """Construct the Auth0 /authorize URL for browser-based step-up.

    The operator opens this URL, authenticates against Auth0 (with
    whatever MFA/SSO their tenant requires), and Auth0 redirects to
    ``redirect_uri`` with ``?code=...&state=<challenge_id>``. The
    receiving service swaps the code for an access token and submits it
    to ``recorder.approve(challenge_id, token)``.

    ``code_challenge`` enables PKCE; pass the SHA-256 of a random
    ``code_verifier`` and use the verifier when exchanging the code at
    the token endpoint. Strongly recommended for native CLI tools and
    SPAs (Auth0 requires it for native apps).
    """
    if tenant.client_id is None:
        raise ValueError("Auth0Tenant.client_id is required for the authorize URL")
    params: dict[str, str] = {
        "client_id": tenant.client_id,
        "audience": tenant.audience,
        "scope": tenant.scope,
        "response_type": "code",
        "redirect_uri": redirect_uri,
        "state": challenge_id,
    }
    if code_challenge is not None:
        params["code_challenge"] = code_challenge
        params["code_challenge_method"] = "S256"
    if additional_params:
        params.update(additional_params)
    return f"{tenant.authorize_url}?{urllib.parse.urlencode(params)}"


def make_pkce_pair() -> tuple[str, str]:
    """Generate a PKCE ``(code_verifier, code_challenge)`` pair.

    The verifier is a 64-character urlsafe random string. The challenge
    is the base64url-encoded SHA-256 of the verifier. Use the challenge
    in ``build_authorize_url`` and the verifier when exchanging the
    code at the token endpoint.
    """
    import base64
    import hashlib

    verifier = secrets.token_urlsafe(48)[:64]
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    return verifier, challenge


@dataclass(frozen=True)
class DeviceAuthorization:
    """Response from ``/oauth/device/code``.

    Show the operator ``user_code`` and direct them to
    ``verification_uri`` (or open ``verification_uri_complete`` directly
    on their phone, which embeds the user_code). Pass ``device_code``
    to ``poll_device_token``.
    """

    device_code: str
    user_code: str
    verification_uri: str
    verification_uri_complete: str
    expires_in: int
    interval: int


def start_device_flow(
    tenant: Auth0Tenant,
    *,
    timeout_seconds: float = _DEFAULT_HTTP_TIMEOUT,
) -> DeviceAuthorization:
    """POST to Auth0's device code endpoint, return what to show the user.

    The CLI flow: print ``user_code`` and ``verification_uri`` to the
    terminal, optionally render ``verification_uri_complete`` as a QR
    code, then call ``poll_device_token`` and block until the operator
    finishes authenticating on their phone or laptop.
    """
    if tenant.client_id is None:
        raise ValueError("Auth0Tenant.client_id is required for device flow")
    body = urllib.parse.urlencode(
        {
            "client_id": tenant.client_id,
            "audience": tenant.audience,
            "scope": tenant.scope,
        },
    ).encode("ascii")
    req = urllib.request.Request(  # noqa: S310 - URL is operator-supplied tenant
        tenant.device_code_url,
        data=body,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=timeout_seconds) as raw:  # noqa: S310
        payload: dict[str, Any] = json.loads(raw.read())
    return DeviceAuthorization(
        device_code=payload["device_code"],
        user_code=payload["user_code"],
        verification_uri=payload["verification_uri"],
        verification_uri_complete=payload.get(
            "verification_uri_complete",
            payload["verification_uri"],
        ),
        expires_in=int(payload.get("expires_in", 900)),
        interval=int(payload.get("interval", 5)),
    )


def poll_device_token(
    tenant: Auth0Tenant,
    device_code: str,
    *,
    interval: int = 5,
    max_poll_seconds: float = _DEFAULT_DEVICE_POLL_TIMEOUT,
) -> str:
    """Poll Auth0's token endpoint until the operator completes the flow.

    Returns the raw access token JWT on success. Raises
    ``Auth0DeviceFlowError`` on access_denied, expired_token, or
    timeout.
    """
    if tenant.client_id is None:
        raise ValueError("Auth0Tenant.client_id is required for device flow")
    deadline = time.monotonic() + max_poll_seconds
    body = urllib.parse.urlencode(
        {
            "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
            "device_code": device_code,
            "client_id": tenant.client_id,
        },
    ).encode("ascii")

    while time.monotonic() < deadline:
        req = urllib.request.Request(  # noqa: S310 - URL is operator-supplied tenant
            tenant.token_url,
            data=body,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=_DEFAULT_HTTP_TIMEOUT) as raw:  # noqa: S310
                payload: dict[str, Any] = json.loads(raw.read())
            token = payload.get("access_token")
            if not isinstance(token, str):
                raise Auth0DeviceFlowError(f"token endpoint returned no access_token: {payload}")
            return token
        except urllib.error.HTTPError as exc:
            error_payload = _safe_json(exc)
            error = error_payload.get("error", "")
            if error == "authorization_pending":
                time.sleep(interval)
                continue
            if error == "slow_down":
                interval = max(interval + 1, interval * 2)
                time.sleep(interval)
                continue
            if error == "access_denied":
                raise Auth0DeviceFlowError("operator denied the approval") from exc
            if error == "expired_token":
                raise Auth0DeviceFlowError("device code expired before approval") from exc
            raise Auth0DeviceFlowError(f"unexpected device-flow error: {error_payload}") from exc
    raise Auth0DeviceFlowError(
        f"device flow timed out after {max_poll_seconds} seconds without approval",
    )


def _safe_json(exc: urllib.error.HTTPError) -> dict[str, Any]:
    try:
        body = exc.read().decode("utf-8", errors="replace")
        parsed = json.loads(body)
    except (ValueError, json.JSONDecodeError):
        return {"error": "unparseable", "raw": ""}
    return parsed if isinstance(parsed, dict) else {"error": "unparseable", "raw": body}


class Auth0DeviceFlowError(Exception):
    """Raised when the device authorization flow cannot complete.

    Distinguished from ``ApprovalInvalidError`` (which is about token
    *verification* failing): this error means the user never produced
    a token at all, either because they denied, the code expired, or
    the polling timed out.
    """
