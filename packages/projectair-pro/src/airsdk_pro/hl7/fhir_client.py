"""FHIR R4 server push client with SMART on FHIR (OAuth2 client credentials) auth.

Sends a FHIR transaction Bundle to a FHIR R4 server. Supports unauthenticated
mode and OAuth2 client credentials grant (SMART on FHIR). On a 401 response the
client refreshes its cached token and retries once before returning a failure
result.

All methods return :class:`FHIRPushResult` on error rather than raising so the
caller can decide how to handle failures without wrapping every call in a
try/except.
"""
from __future__ import annotations

import time
from typing import Any

import httpx

from airsdk_pro.gate import requires_pro
from airsdk_pro.hl7.capture import HL7_FHIR_FEATURE
from airsdk_pro.hl7.types import FHIRPushResult

_TOKEN_SKEW_SECONDS = 30


def _count_entries(response_body: bytes) -> tuple[int, int]:
    """Parse a transaction-response Bundle and count created / failed entries.

    Returns ``(resources_created, resources_failed)``.

    A "created" entry has a ``response.status`` that starts with ``"201"``.
    A "failed" entry has a ``response.status`` that starts with ``"4"`` or ``"5"``.
    Entries with other status prefixes (``"200"``) are neither created nor failed.
    """
    import json as _json

    try:
        body: dict[str, Any] = _json.loads(response_body)
    except (ValueError, UnicodeDecodeError):
        return 0, 0

    entries: list[dict[str, Any]] = body.get("entry", [])
    created = 0
    failed = 0
    for entry in entries:
        status_str = str((entry.get("response") or {}).get("status", ""))
        if status_str.startswith("201"):
            created += 1
        elif status_str and (status_str[0] == "4" or status_str[0] == "5"):
            failed += 1
    return created, failed


def _build_transaction_bundle(resources: list[dict[str, Any]]) -> dict[str, Any]:
    """Wrap a list of FHIR resource dicts in a FHIR R4 transaction Bundle."""
    entries: list[dict[str, Any]] = []
    for resource in resources:
        resource_type = resource.get("resourceType", "Resource")
        entries.append({
            "resource": resource,
            "request": {
                "method": "POST",
                "url": resource_type,
            },
        })
    return {
        "resourceType": "Bundle",
        "type": "transaction",
        "entry": entries,
    }


class FHIRClient:
    """Push FHIR R4 transaction Bundles to a FHIR server.

    Parameters
    ----------
    fhir_url:
        Base URL of the FHIR R4 server (e.g. ``https://fhir.example.com/R4``).
    client_id:
        OAuth2 client ID for SMART on FHIR client credentials grant.
    client_secret:
        OAuth2 client secret.
    token_url:
        OAuth2 token endpoint URL.
    scopes:
        OAuth2 scopes to request. Defaults to ``["system/*.write"]``.
    timeout:
        HTTP request timeout in seconds. Defaults to 30.
    client:
        Optional pre-built :class:`httpx.Client`. When provided, ``timeout``
        is ignored for the injected client. Useful for testing with
        ``httpx.MockTransport``.
    """

    def __init__(
        self,
        fhir_url: str,
        *,
        client_id: str | None = None,
        client_secret: str | None = None,
        token_url: str | None = None,
        scopes: list[str] | None = None,
        timeout: float = 30.0,
        client: httpx.Client | None = None,
    ) -> None:
        self._fhir_url = fhir_url.rstrip("/")
        self._client_id = client_id
        self._client_secret = client_secret
        self._token_url = token_url
        self._scopes: list[str] = scopes if scopes is not None else ["system/*.write"]
        self._timeout = timeout
        self._http = client if client is not None else httpx.Client(timeout=timeout)
        self._cached_token: str | None = None
        self._token_expires_at: float = 0.0

    @property
    def _auth_enabled(self) -> bool:
        return bool(self._token_url and self._client_id and self._client_secret)

    def _fetch_token(self) -> str:
        """Fetch a new OAuth2 access token via client credentials grant.

        Raises :class:`httpx.HTTPStatusError` if the token endpoint returns
        a non-2xx response; callers should catch and convert to a failure result.
        """
        assert self._token_url is not None
        assert self._client_id is not None
        assert self._client_secret is not None

        response = self._http.post(
            self._token_url,
            data={
                "grant_type": "client_credentials",
                "client_id": self._client_id,
                "client_secret": self._client_secret,
                "scope": " ".join(self._scopes),
            },
        )
        response.raise_for_status()
        body: dict[str, Any] = response.json()
        token: str = str(body["access_token"])
        expires_in = int(body.get("expires_in", 3600))
        self._cached_token = token
        self._token_expires_at = time.time() + expires_in - _TOKEN_SKEW_SECONDS
        return token

    def _get_token(self) -> str:
        """Return a valid cached token, fetching a new one if needed."""
        if self._cached_token is None or time.time() >= self._token_expires_at:
            return self._fetch_token()
        return self._cached_token

    def _invalidate_token(self) -> None:
        """Discard the cached token so the next call fetches a fresh one."""
        self._cached_token = None
        self._token_expires_at = 0.0

    def _do_push(self, bundle: dict[str, Any], token: str | None) -> httpx.Response:
        """Send the transaction Bundle to the FHIR server."""
        import json as _json

        headers: dict[str, str] = {
            "Content-Type": "application/fhir+json",
            "Accept": "application/fhir+json",
        }
        if token is not None:
            headers["Authorization"] = f"Bearer {token}"

        return self._http.post(
            self._fhir_url,
            content=_json.dumps(bundle).encode("utf-8"),
            headers=headers,
        )

    @requires_pro(feature=HL7_FHIR_FEATURE)
    def push_bundle(self, resources: list[dict[str, Any]]) -> FHIRPushResult:
        """Push a list of FHIR R4 resource dicts as a transaction Bundle.

        Wraps ``resources`` in a FHIR transaction Bundle (POST entry per resource)
        and sends it to the configured FHIR server. On 401, refreshes the OAuth2
        token and retries once. Returns :class:`FHIRPushResult` in all cases; does
        not raise on HTTP errors.

        Parameters
        ----------
        resources:
            List of FHIR resource dicts. Each must include ``"resourceType"``.

        Returns
        -------
        FHIRPushResult
            ``success=True`` when the server returns 2xx. ``resources_created``
            counts entries whose ``response.status`` starts with ``"201"``.
            ``resources_failed`` counts entries whose status starts with ``"4"``
            or ``"5"``.
        """
        bundle = _build_transaction_bundle(resources)

        try:
            token: str | None = self._get_token() if self._auth_enabled else None
        except Exception as exc:
            return FHIRPushResult(
                success=False,
                status_code=0,
                error=f"token fetch failed: {exc}",
            )

        try:
            response = self._do_push(bundle, token)
        except Exception as exc:
            return FHIRPushResult(
                success=False,
                status_code=0,
                error=f"request failed: {exc}",
            )

        if response.status_code == 401 and self._auth_enabled:
            # Invalidate the cached token and retry once.
            self._invalidate_token()
            try:
                token = self._fetch_token()
                response = self._do_push(bundle, token)
            except Exception as exc:
                return FHIRPushResult(
                    success=False,
                    status_code=0,
                    error=f"retry failed: {exc}",
                )

        status_code = response.status_code

        if not (200 <= status_code < 300):
            return FHIRPushResult(
                success=False,
                status_code=status_code,
                error=f"FHIR server returned HTTP {status_code}",
            )

        resources_created, resources_failed = _count_entries(response.content)
        return FHIRPushResult(
            success=True,
            status_code=status_code,
            resources_created=resources_created,
            resources_failed=resources_failed,
        )


__all__ = ["FHIRClient", "HL7_FHIR_FEATURE"]
