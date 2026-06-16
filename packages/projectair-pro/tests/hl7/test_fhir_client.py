"""Tests for FHIR R4 server push client (Task 7)."""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

import httpx
import pytest

from _helpers import requires_vendor_key
from airsdk_pro.hl7.capture import HL7_FHIR_FEATURE
from airsdk_pro.hl7.fhir_client import FHIRClient
from airsdk_pro.hl7.types import FHIRPushResult
from airsdk_pro.license import LicenseInvalidError, LicenseMissingError, install_license, load_license

# ---------------------------------------------------------------------------
# Fixtures and helpers
# ---------------------------------------------------------------------------

_TOKEN_URL = "https://auth.example.com/oauth2/token"
_FHIR_URL = "https://fhir.example.com/R4"

_SAMPLE_RESOURCES = [
    {"resourceType": "Patient", "id": "p1"},
    {"resourceType": "Observation", "id": "obs1"},
]


def _bundle_response(entries: list[dict[str, Any]]) -> dict[str, Any]:
    """Build a minimal FHIR transaction-response Bundle."""
    return {
        "resourceType": "Bundle",
        "type": "transaction-response",
        "entry": entries,
    }


def _created_entry(resource_type: str = "Patient") -> dict[str, Any]:
    return {"response": {"status": "201 Created", "resourceType": resource_type}}


def _ok_entry() -> dict[str, Any]:
    return {"response": {"status": "200 OK"}}


def _failed_entry() -> dict[str, Any]:
    return {"response": {"status": "400 Bad Request"}}


def _token_response(token: str = "access-token-abc") -> dict[str, Any]:
    return {"access_token": token, "token_type": "Bearer", "expires_in": 3600}


def _make_client(
    *,
    fhir_handler: Any,
    token_handler: Any | None = None,
) -> tuple[FHIRClient, dict[str, Any]]:
    """Build an FHIRClient with a MockTransport that dispatches by URL."""
    call_log: dict[str, Any] = {"fhir_calls": 0, "token_calls": 0}

    def _transport_handler(request: httpx.Request) -> httpx.Response:
        if str(request.url).startswith(_TOKEN_URL):
            call_log["token_calls"] += 1
            if token_handler is not None:
                return token_handler(request)
            return httpx.Response(200, json=_token_response())
        call_log["fhir_calls"] += 1
        return fhir_handler(request)

    mock_transport = httpx.MockTransport(_transport_handler)
    http_client = httpx.Client(transport=mock_transport)
    fhir_client = FHIRClient(
        _FHIR_URL,
        client_id="client-id",
        client_secret="client-secret",  # noqa: S106
        token_url=_TOKEN_URL,
        client=http_client,
    )
    return fhir_client, call_log


@pytest.fixture
def licensed(
    tmp_path: Path,
    issue_token: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> Path:
    """Install a Pro license with the HL7 FHIR feature and route the gate to it."""
    token = issue_token(
        email="fhir-client-tests@vindicara.io",
        tier="individual",
        features=(HL7_FHIR_FEATURE,),
    )
    license_path = tmp_path / "license.json"
    install_license(token, path=license_path)
    monkeypatch.setattr(
        "airsdk_pro.gate.load_license", lambda: load_license(license_path)
    )
    return license_path


# ---------------------------------------------------------------------------
# test_push_bundle_success
# ---------------------------------------------------------------------------


@requires_vendor_key
def test_push_bundle_success(licensed: Path) -> None:
    """200 response with transaction-response Bundle yields success=True and counts 201 entries."""
    def fhir_handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        assert body["resourceType"] == "Bundle"
        assert body["type"] == "transaction"
        return httpx.Response(
            200,
            json=_bundle_response([_created_entry("Patient"), _created_entry("Observation")]),
        )

    client, _ = _make_client(fhir_handler=fhir_handler)
    result = client.push_bundle(_SAMPLE_RESOURCES)

    assert isinstance(result, FHIRPushResult)
    assert result.success is True
    assert result.status_code == 200
    assert result.resources_created == 2
    assert result.resources_failed == 0
    assert result.error is None


# ---------------------------------------------------------------------------
# test_push_bundle_auth_failure_retries
# ---------------------------------------------------------------------------


@requires_vendor_key
def test_push_bundle_auth_failure_retries(licensed: Path) -> None:
    """First FHIR call returns 401; client refreshes token and retries once, then succeeds."""
    fhir_call_count = {"n": 0}

    def fhir_handler(request: httpx.Request) -> httpx.Response:
        fhir_call_count["n"] += 1
        if fhir_call_count["n"] == 1:
            return httpx.Response(401, text="Unauthorized")
        return httpx.Response(
            200,
            json=_bundle_response([_created_entry("Patient")]),
        )

    client, call_log = _make_client(fhir_handler=fhir_handler)
    result = client.push_bundle(_SAMPLE_RESOURCES)

    assert fhir_call_count["n"] == 2, "expected exactly 2 FHIR calls (original + retry)"
    assert call_log["token_calls"] == 2, "expected token to be fetched twice (initial + refresh)"
    assert result.success is True
    assert result.status_code == 200
    assert result.resources_created == 1


# ---------------------------------------------------------------------------
# test_push_bundle_returns_failure_on_500
# ---------------------------------------------------------------------------


@requires_vendor_key
def test_push_bundle_returns_failure_on_500(licensed: Path) -> None:
    """500 response does not raise; returns FHIRPushResult(success=False, status_code=500)."""
    def fhir_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(500, text="Internal Server Error")

    client, _ = _make_client(fhir_handler=fhir_handler)
    result = client.push_bundle(_SAMPLE_RESOURCES)

    assert result.success is False
    assert result.status_code == 500
    assert result.resources_created == 0
    assert result.error is not None


# ---------------------------------------------------------------------------
# test_push_bundle_returns_failure_on_4xx
# ---------------------------------------------------------------------------


@requires_vendor_key
def test_push_bundle_returns_failure_on_4xx(licensed: Path) -> None:
    """400 Bad Request returns FHIRPushResult(success=False) without raising."""
    def fhir_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(400, json={"issue": [{"severity": "error"}]})

    client, _ = _make_client(fhir_handler=fhir_handler)
    result = client.push_bundle(_SAMPLE_RESOURCES)

    assert result.success is False
    assert result.status_code == 400


# ---------------------------------------------------------------------------
# test_push_bundle_401_no_retry_when_unauthenticated
# ---------------------------------------------------------------------------


@requires_vendor_key
def test_push_bundle_401_no_retry_when_unauthenticated(licensed: Path) -> None:
    """Without OAuth params, a 401 returns failure immediately with no retry."""
    call_count = {"n": 0}

    def _handler(request: httpx.Request) -> httpx.Response:
        call_count["n"] += 1
        return httpx.Response(401, text="Unauthorized")

    http_client = httpx.Client(transport=httpx.MockTransport(_handler))
    client = FHIRClient(_FHIR_URL, client=http_client)
    result = client.push_bundle(_SAMPLE_RESOURCES)

    assert call_count["n"] == 1, "unauthenticated mode must not retry on 401"
    assert result.success is False
    assert result.status_code == 401


# ---------------------------------------------------------------------------
# test_push_bundle_token_cached_across_calls
# ---------------------------------------------------------------------------


@requires_vendor_key
def test_push_bundle_token_cached_across_calls(licensed: Path) -> None:
    """Token is fetched once and reused for a second push_bundle call."""
    def fhir_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=_bundle_response([_created_entry()]))

    client, call_log = _make_client(fhir_handler=fhir_handler)
    client.push_bundle(_SAMPLE_RESOURCES)
    client.push_bundle(_SAMPLE_RESOURCES)

    assert call_log["token_calls"] == 1, "token should be cached after first fetch"
    assert call_log["fhir_calls"] == 2


# ---------------------------------------------------------------------------
# test_push_bundle_mixed_entry_statuses
# ---------------------------------------------------------------------------


@requires_vendor_key
def test_push_bundle_mixed_entry_statuses(licensed: Path) -> None:
    """201 entries count as created; 4xx entries count as failed."""
    def fhir_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json=_bundle_response([
                _created_entry("Patient"),
                _created_entry("Observation"),
                _failed_entry(),
            ]),
        )

    client, _ = _make_client(fhir_handler=fhir_handler)
    result = client.push_bundle(_SAMPLE_RESOURCES)

    assert result.success is True
    assert result.resources_created == 2
    assert result.resources_failed == 1


# ---------------------------------------------------------------------------
# test_push_bundle_bundle_format
# ---------------------------------------------------------------------------


@requires_vendor_key
def test_push_bundle_bundle_format(licensed: Path) -> None:
    """Outgoing request is a FHIR transaction Bundle with POST request entries per resource."""
    captured: dict[str, Any] = {}

    def fhir_handler(request: httpx.Request) -> httpx.Response:
        captured["body"] = json.loads(request.content)
        captured["content_type"] = request.headers.get("content-type", "")
        return httpx.Response(200, json=_bundle_response([_created_entry()]))

    client, _ = _make_client(fhir_handler=fhir_handler)
    client.push_bundle(_SAMPLE_RESOURCES)

    bundle = captured["body"]
    assert bundle["resourceType"] == "Bundle"
    assert bundle["type"] == "transaction"
    assert "entry" in bundle
    assert len(bundle["entry"]) == len(_SAMPLE_RESOURCES)
    for entry in bundle["entry"]:
        assert entry["request"]["method"] == "POST"
        assert "resource" in entry
    assert "application/fhir+json" in captured["content_type"]


# ---------------------------------------------------------------------------
# Gate: blocks without license
# ---------------------------------------------------------------------------


def test_push_bundle_blocks_without_license(monkeypatch: pytest.MonkeyPatch) -> None:
    """push_bundle raises LicenseMissingError when no license is installed."""
    def _raise() -> Any:
        raise LicenseMissingError("no license")

    monkeypatch.setattr("airsdk_pro.gate.load_license", _raise)

    client = FHIRClient(_FHIR_URL)
    with pytest.raises(LicenseMissingError):
        client.push_bundle(_SAMPLE_RESOURCES)


# ---------------------------------------------------------------------------
# Gate: blocks when feature not in license
# ---------------------------------------------------------------------------


@requires_vendor_key
def test_push_bundle_blocks_when_feature_not_in_license(
    tmp_path: Path,
    issue_token: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """push_bundle raises LicenseInvalidError when license lacks the hl7-fhir-integration feature."""
    token = issue_token(
        email="other@vindicara.io",
        tier="individual",
        features=("report-nist-ai-rmf",),
    )
    license_path = tmp_path / "license.json"
    install_license(token, path=license_path)
    monkeypatch.setattr(
        "airsdk_pro.gate.load_license", lambda: load_license(license_path)
    )

    client = FHIRClient(_FHIR_URL)
    with pytest.raises(LicenseInvalidError):
        client.push_bundle(_SAMPLE_RESOURCES)
