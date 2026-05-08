"""SIEM push helpers (Pro) — Datadog, Splunk HEC, Sumo, Sentinel."""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import uuid4

import httpx
import pytest
from airsdk.types import (
    AgDRPayload,
    AgDRRecord,
    Finding,
    ForensicReport,
    StepKind,
    VerificationResult,
    VerificationStatus,
)

from _helpers import requires_vendor_key
from airsdk_pro.license import (
    LicenseInvalidError,
    LicenseMissingError,
    install_license,
    load_license,
)
from airsdk_pro.siem import (
    SIEM_INTEGRATIONS_FEATURE,
    SiemConfigError,
    SiemPushError,
    push_to_datadog,
    push_to_sentinel,
    push_to_splunk_hec,
    push_to_sumo,
)

DUMMY_HASH = "0" * 64
DUMMY_SIG = "aa" * 64
DUMMY_KEY = "bb" * 32


def _record() -> AgDRRecord:
    return AgDRRecord(
        step_id="test-step-1",
        timestamp="2026-04-21T12:00:00Z",
        kind=StepKind.LLM_START,
        payload=AgDRPayload.model_validate({}),
        prev_hash=DUMMY_HASH,
        content_hash=DUMMY_HASH,
        signature=DUMMY_SIG,
        signer_key=DUMMY_KEY,
    )


def _finding(severity: str = "high", detector_id: str = "ASI01") -> Finding:
    return Finding(
        detector_id=detector_id,
        title=f"{detector_id} test",
        severity=severity,
        step_id="test-step-1",
        step_index=0,
        description=f"{detector_id} {severity} demo",
    )


def _report(findings: list[Finding] | None = None) -> ForensicReport:
    return ForensicReport(
        air_version="0.7.1",
        report_id=str(uuid4()),
        source_log="/var/log/air/fixture.log",
        generated_at=datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        records=1,
        conversations=1,
        verification=VerificationResult(status=VerificationStatus.OK, records_verified=1),
        findings=findings if findings is not None else [_finding()],
    )


@pytest.fixture
def licensed(
    tmp_path: Path,
    issue_token: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> Path:
    """Install a Pro license with the SIEM feature flag and route the gate to it."""
    token = issue_token(
        email="siem-tests@vindicara.io",
        tier="team",
        features=(SIEM_INTEGRATIONS_FEATURE,),
    )
    license_path = tmp_path / "license.json"
    install_license(token, path=license_path)
    monkeypatch.setattr(
        "airsdk_pro.gate.load_license", lambda: load_license(license_path)
    )
    return license_path


def _capturing_client(captured: dict[str, Any], status_code: int = 202, body: str = '{"status":"ok"}') -> httpx.Client:
    """Build an httpx.Client backed by MockTransport that captures the request."""
    def _handler(request: httpx.Request) -> httpx.Response:
        captured["url"] = str(request.url)
        captured["method"] = request.method
        captured["headers"] = dict(request.headers)
        captured["body"] = request.content.decode("utf-8")
        return httpx.Response(status_code, text=body)

    return httpx.Client(transport=httpx.MockTransport(_handler))


# -- Datadog -------------------------------------------------------------


@requires_vendor_key
def test_datadog_push_succeeds_and_targets_correct_endpoint(licensed: Path) -> None:
    captured: dict[str, Any] = {}
    with _capturing_client(captured) as client:
        result = push_to_datadog(
            _report(),
            api_key="dd-api-key-fake",
            client=client,
        )
    assert result.vendor == "datadog"
    assert result.events_sent == 1
    assert result.http_status == 202
    assert captured["url"] == "https://http-intake.logs.datadoghq.com/api/v2/logs"
    assert captured["headers"]["dd-api-key"] == "dd-api-key-fake"
    parsed = json.loads(captured["body"])
    assert isinstance(parsed, list)
    assert len(parsed) == 1
    assert parsed[0]["ddsource"] == "vindicara-air"
    assert "detector_id:ASI01" in parsed[0]["ddtags"]


@requires_vendor_key
def test_datadog_eu_site_changes_endpoint(licensed: Path) -> None:
    captured: dict[str, Any] = {}
    with _capturing_client(captured) as client:
        push_to_datadog(_report(), api_key="k", site="datadoghq.eu", client=client)
    assert captured["url"] == "https://http-intake.logs.datadoghq.eu/api/v2/logs"


@requires_vendor_key
def test_datadog_min_severity_filters_lower_findings(licensed: Path) -> None:
    captured: dict[str, Any] = {}
    findings = [_finding(severity="low"), _finding(severity="critical", detector_id="ASI03")]
    with _capturing_client(captured) as client:
        result = push_to_datadog(_report(findings=findings), api_key="k", min_severity="high", client=client)
    assert result.events_sent == 1
    parsed = json.loads(captured["body"])
    assert parsed[0]["vindicara"]["severity"] == "critical"


@requires_vendor_key
def test_datadog_empty_findings_skips_request(licensed: Path) -> None:
    captured: dict[str, Any] = {}
    with _capturing_client(captured) as client:
        result = push_to_datadog(_report(findings=[]), api_key="k", client=client)
    assert result.events_sent == 0
    assert "url" not in captured  # no request was made


@requires_vendor_key
def test_datadog_missing_api_key_raises_config_error(licensed: Path) -> None:
    with pytest.raises(SiemConfigError):
        push_to_datadog(_report(), api_key="")


@requires_vendor_key
def test_datadog_non_2xx_raises_push_error(licensed: Path) -> None:
    captured: dict[str, Any] = {}
    with (
        _capturing_client(captured, status_code=403, body="forbidden") as client,
        pytest.raises(SiemPushError) as exc_info,
    ):
        push_to_datadog(_report(), api_key="k", client=client)
    assert exc_info.value.status_code == 403


# -- Splunk HEC ----------------------------------------------------------


@requires_vendor_key
def test_splunk_hec_push_succeeds_and_targets_url(licensed: Path) -> None:
    captured: dict[str, Any] = {}
    with _capturing_client(captured) as client:
        result = push_to_splunk_hec(
            _report(),
            hec_url="https://hec.splunkcloud.com:8088/services/collector",
            hec_token="splunk-token",  # noqa: S106
            client=client,
        )
    assert result.vendor == "splunk_hec"
    assert result.events_sent == 1
    assert captured["url"] == "https://hec.splunkcloud.com:8088/services/collector"
    assert captured["headers"]["authorization"] == "Splunk splunk-token"


@requires_vendor_key
def test_splunk_hec_payload_is_concatenated_envelopes(licensed: Path) -> None:
    """HEC expects newline-delimited JSON envelopes, not a JSON array."""
    captured: dict[str, Any] = {}
    findings = [_finding(detector_id="ASI01"), _finding(detector_id="ASI02")]
    with _capturing_client(captured) as client:
        push_to_splunk_hec(
            _report(findings=findings),
            hec_url="https://hec/services/collector",
            hec_token="t",  # noqa: S106
            client=client,
        )
    lines = captured["body"].split("\n")
    assert len(lines) == 2
    parsed = [json.loads(line) for line in lines]
    assert parsed[0]["sourcetype"] == "vindicara_air:finding"
    assert parsed[0]["event"]["vindicara"]["detector_id"] == "ASI01"


@requires_vendor_key
def test_splunk_hec_index_passed_through(licensed: Path) -> None:
    captured: dict[str, Any] = {}
    with _capturing_client(captured) as client:
        push_to_splunk_hec(
            _report(),
            hec_url="https://hec/services/collector",
            hec_token="t",  # noqa: S106
            index="airsec",
            client=client,
        )
    parsed = json.loads(captured["body"].split("\n")[0])
    assert parsed["index"] == "airsec"


@requires_vendor_key
def test_splunk_hec_missing_token_raises_config_error(licensed: Path) -> None:
    with pytest.raises(SiemConfigError):
        push_to_splunk_hec(_report(), hec_url="https://hec", hec_token="")


# -- Sumo ----------------------------------------------------------------


@requires_vendor_key
def test_sumo_push_succeeds_with_optional_metadata(licensed: Path) -> None:
    captured: dict[str, Any] = {}
    with _capturing_client(captured) as client:
        result = push_to_sumo(
            _report(),
            http_source_url="https://endpoint.collection.sumologic.com/receiver/v1/http/TOKEN",
            category="vindicara/air",
            host="agent-01",
            name="vindicara-air-pro",
            client=client,
        )
    assert result.vendor == "sumo"
    assert result.events_sent == 1
    assert captured["headers"]["x-sumo-category"] == "vindicara/air"
    assert captured["headers"]["x-sumo-host"] == "agent-01"
    assert captured["headers"]["x-sumo-name"] == "vindicara-air-pro"
    parsed = json.loads(captured["body"].split("\n")[0])
    assert parsed["vindicara"]["detector_id"] == "ASI01"


@requires_vendor_key
def test_sumo_missing_url_raises_config_error(licensed: Path) -> None:
    with pytest.raises(SiemConfigError):
        push_to_sumo(_report(), http_source_url="")


# -- Sentinel ------------------------------------------------------------


@requires_vendor_key
def test_sentinel_push_signs_request_with_hmac_sha256(licensed: Path) -> None:
    captured: dict[str, Any] = {}
    workspace_id = "11111111-2222-3333-4444-555555555555"
    shared_key = base64.b64encode(b"sentinel-shared-key-secret").decode("ascii")
    fixed_time = datetime(2026, 5, 8, 12, 0, 0, tzinfo=UTC)
    body_capture: dict[str, Any] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured.update(
            url=str(request.url),
            method=request.method,
            headers=dict(request.headers),
            body=request.content.decode("utf-8"),
        )
        body_capture["bytes"] = request.content
        return httpx.Response(200)

    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        result = push_to_sentinel(
            _report(),
            workspace_id=workspace_id,
            shared_key=shared_key,
            client=client,
            now=fixed_time,
        )

    assert result.vendor == "sentinel"
    assert captured["url"] == (
        f"https://{workspace_id}.ods.opinsights.azure.com"
        "/api/logs?api-version=2016-04-01"
    )
    assert captured["headers"]["log-type"] == "VindicaraAIR"
    assert captured["headers"]["x-ms-date"] == "Fri, 08 May 2026 12:00:00 GMT"

    auth_header = captured["headers"]["authorization"]
    assert auth_header.startswith(f"SharedKey {workspace_id}:")
    expected_canonical = (
        f"POST\n{len(body_capture['bytes'])}\napplication/json\n"
        f"x-ms-date:Fri, 08 May 2026 12:00:00 GMT\n/api/logs"
    ).encode()
    expected_sig = base64.b64encode(
        hmac.new(base64.b64decode(shared_key), expected_canonical, hashlib.sha256).digest()
    ).decode("ascii")
    assert auth_header == f"SharedKey {workspace_id}:{expected_sig}"


@requires_vendor_key
def test_sentinel_missing_workspace_id_raises_config_error(licensed: Path) -> None:
    with pytest.raises(SiemConfigError):
        push_to_sentinel(_report(), workspace_id="", shared_key="abc")


@requires_vendor_key
def test_sentinel_invalid_base64_shared_key_raises_config_error(licensed: Path) -> None:
    with pytest.raises(SiemConfigError):
        push_to_sentinel(_report(), workspace_id="ws", shared_key="not-base64!@#$%")


# -- Gate behaviour ------------------------------------------------------


def test_datadog_push_blocks_without_license(monkeypatch: pytest.MonkeyPatch) -> None:
    def _raise() -> Any:
        raise LicenseMissingError("no license")

    monkeypatch.setattr("airsdk_pro.gate.load_license", _raise)
    with pytest.raises(LicenseMissingError):
        push_to_datadog(_report(), api_key="k")


@requires_vendor_key
def test_datadog_push_blocks_when_feature_not_in_license(
    tmp_path: Path,
    issue_token: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
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
    with pytest.raises(LicenseInvalidError):
        push_to_datadog(_report(), api_key="k")
