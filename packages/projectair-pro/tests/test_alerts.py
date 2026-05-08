"""Incident alerting hooks (Pro) — Slack, PagerDuty, generic webhook."""
from __future__ import annotations

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
    Finding,
    ForensicReport,
    VerificationResult,
    VerificationStatus,
)

from _helpers import requires_vendor_key
from airsdk_pro.alerts import (
    INCIDENT_WORKFLOWS_FEATURE,
    AlertConfigError,
    AlertPushError,
    alert_to_pagerduty,
    alert_to_slack,
    alert_to_webhook,
)
from airsdk_pro.alerts.pagerduty import EVENTS_URL as PD_EVENTS_URL
from airsdk_pro.alerts.webhook import SIGNATURE_HEADER as WEBHOOK_SIG_HEADER
from airsdk_pro.license import (
    LicenseInvalidError,
    LicenseMissingError,
    install_license,
    load_license,
)


def _finding(severity: str = "high", detector_id: str = "ASI01", description: str = "test") -> Finding:
    return Finding(
        detector_id=detector_id,
        title=f"{detector_id} test",
        severity=severity,
        step_id=f"step-{detector_id}",
        step_index=0,
        description=description,
    )


def _report(findings: list[Finding] | None = None) -> ForensicReport:
    return ForensicReport(
        air_version="0.7.1",
        report_id=str(uuid4()),
        source_log="/var/log/air/fixture.log",
        generated_at=datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        records=10,
        conversations=1,
        verification=VerificationResult(status=VerificationStatus.OK, records_verified=10),
        findings=findings if findings is not None else [_finding()],
    )


@pytest.fixture
def licensed(
    tmp_path: Path,
    issue_token: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> Path:
    token = issue_token(
        email="alerts-tests@vindicara.io",
        tier="team",
        features=(INCIDENT_WORKFLOWS_FEATURE,),
    )
    license_path = tmp_path / "license.json"
    install_license(token, path=license_path)
    monkeypatch.setattr(
        "airsdk_pro.gate.load_license", lambda: load_license(license_path)
    )
    return license_path


def _capturing_client(
    captured: list[dict[str, Any]],
    status_code: int = 200,
) -> httpx.Client:
    """httpx.Client that records every request made."""
    def handler(request: httpx.Request) -> httpx.Response:
        captured.append({
            "url": str(request.url),
            "method": request.method,
            "headers": dict(request.headers),
            "body": request.content.decode("utf-8") if request.content else "",
        })
        return httpx.Response(status_code)
    return httpx.Client(transport=httpx.MockTransport(handler))


# -- Slack ---------------------------------------------------------------


@requires_vendor_key
def test_slack_alert_sends_blocks_payload(licensed: Path) -> None:
    captured: list[dict[str, Any]] = []
    findings = [_finding(severity="critical", detector_id="ASI03")]
    with _capturing_client(captured) as client:
        result = alert_to_slack(
            _report(findings=findings),
            webhook_url="https://hooks.slack.com/services/X/Y/Z",
            client=client,
        )
    assert result.target == "slack"
    assert result.findings_alerted == 1
    assert len(captured) == 1
    payload = json.loads(captured[0]["body"])
    assert "blocks" in payload
    assert payload["blocks"][0]["type"] == "header"
    assert "ASI03" in json.dumps(payload)


@requires_vendor_key
def test_slack_alert_skips_when_no_finding_meets_threshold(licensed: Path) -> None:
    captured: list[dict[str, Any]] = []
    findings = [_finding(severity="low"), _finding(severity="medium")]
    with _capturing_client(captured) as client:
        result = alert_to_slack(
            _report(findings=findings),
            webhook_url="https://hooks.slack.com/services/X/Y/Z",
            min_severity="high",
            client=client,
        )
    assert result.findings_alerted == 0
    assert captured == []  # no HTTP call


@requires_vendor_key
def test_slack_alert_missing_url_raises_config_error(licensed: Path) -> None:
    with pytest.raises(AlertConfigError):
        alert_to_slack(_report(), webhook_url="")


@requires_vendor_key
def test_slack_alert_invalid_severity_raises_config_error(licensed: Path) -> None:
    with pytest.raises(AlertConfigError):
        alert_to_slack(_report(), webhook_url="https://hooks", min_severity="extreme")


@requires_vendor_key
def test_slack_alert_non_2xx_raises_push_error(licensed: Path) -> None:
    captured: list[dict[str, Any]] = []
    with (
        _capturing_client(captured, status_code=500) as client,
        pytest.raises(AlertPushError) as exc_info,
    ):
        alert_to_slack(_report(), webhook_url="https://hooks", client=client)
    assert exc_info.value.status_code == 500


# -- PagerDuty -----------------------------------------------------------


@requires_vendor_key
def test_pagerduty_alert_sends_one_event_per_finding(licensed: Path) -> None:
    captured: list[dict[str, Any]] = []
    findings = [
        _finding(severity="critical", detector_id="ASI03"),
        _finding(severity="high", detector_id="ASI04-PD"),
    ]
    with _capturing_client(captured, status_code=202) as client:
        result = alert_to_pagerduty(
            _report(findings=findings),
            integration_key="pd-int-key",
            client=client,
        )
    assert result.target == "pagerduty"
    assert result.findings_alerted == 2
    assert len(captured) == 2
    for req in captured:
        assert req["url"] == PD_EVENTS_URL
        body = json.loads(req["body"])
        assert body["routing_key"] == "pd-int-key"
        assert body["event_action"] == "trigger"
        assert "dedup_key" in body
        assert body["payload"]["custom_details"]["chain_status"] == "ok"


@requires_vendor_key
def test_pagerduty_severity_mapping(licensed: Path) -> None:
    captured: list[dict[str, Any]] = []
    findings = [
        _finding(severity="critical", detector_id="A"),
        _finding(severity="high", detector_id="B"),
    ]
    with _capturing_client(captured) as client:
        alert_to_pagerduty(_report(findings=findings), integration_key="k", client=client)
    severities = [json.loads(req["body"])["payload"]["severity"] for req in captured]
    assert severities == ["critical", "error"]


@requires_vendor_key
def test_pagerduty_skips_when_no_finding_meets_threshold(licensed: Path) -> None:
    captured: list[dict[str, Any]] = []
    with _capturing_client(captured) as client:
        result = alert_to_pagerduty(
            _report(findings=[_finding(severity="low")]),
            integration_key="k",
            min_severity="high",
            client=client,
        )
    assert result.findings_alerted == 0
    assert captured == []


@requires_vendor_key
def test_pagerduty_missing_integration_key_raises_config_error(licensed: Path) -> None:
    with pytest.raises(AlertConfigError):
        alert_to_pagerduty(_report(), integration_key="")


@requires_vendor_key
def test_pagerduty_dedup_key_is_stable_per_finding(licensed: Path) -> None:
    """Same report + same finding should produce the same dedup_key, so re-running does not fan out."""
    captured: list[dict[str, Any]] = []
    finding = _finding(severity="critical", detector_id="ASI03")
    report = _report(findings=[finding])
    with _capturing_client(captured) as c1:
        alert_to_pagerduty(report, integration_key="k", client=c1)
    with _capturing_client(captured) as c2:
        alert_to_pagerduty(report, integration_key="k", client=c2)
    keys = [json.loads(req["body"])["dedup_key"] for req in captured]
    assert keys[0] == keys[1]


# -- Webhook -------------------------------------------------------------


@requires_vendor_key
def test_webhook_alert_payload_shape(licensed: Path) -> None:
    captured: list[dict[str, Any]] = []
    findings = [_finding(severity="critical", detector_id="ASI03")]
    with _capturing_client(captured) as client:
        result = alert_to_webhook(
            _report(findings=findings),
            url="https://alerts.example.com/air",
            client=client,
        )
    assert result.findings_alerted == 1
    body = json.loads(captured[0]["body"])
    assert body["vendor"] == "vindicara"
    assert body["kind"] == "alert"
    assert body["chain_status"] == "ok"
    assert body["min_severity"] == "high"
    assert len(body["findings"]) == 1
    assert body["findings"][0]["detector_id"] == "ASI03"


@requires_vendor_key
def test_webhook_alert_signs_body_when_secret_set(licensed: Path) -> None:
    captured: list[dict[str, Any]] = []
    secret = "alert-shared-secret-very-long"  # noqa: S105
    findings = [_finding(severity="critical")]
    with _capturing_client(captured) as client:
        alert_to_webhook(
            _report(findings=findings),
            url="https://alerts/x",
            secret=secret,
            client=client,
        )
    sig = captured[0]["headers"][WEBHOOK_SIG_HEADER.lower()]
    assert sig.startswith("sha256=")
    expected = hmac.new(secret.encode("utf-8"), captured[0]["body"].encode("utf-8"), hashlib.sha256).hexdigest()
    assert sig == f"sha256={expected}"


@requires_vendor_key
def test_webhook_alert_no_signature_without_secret(licensed: Path) -> None:
    captured: list[dict[str, Any]] = []
    with _capturing_client(captured) as client:
        alert_to_webhook(_report(findings=[_finding(severity="critical")]), url="https://alerts", client=client)
    assert WEBHOOK_SIG_HEADER.lower() not in captured[0]["headers"]


@requires_vendor_key
def test_webhook_alert_extra_headers_cannot_override_signature(licensed: Path) -> None:
    with pytest.raises(AlertConfigError):
        alert_to_webhook(
            _report(findings=[_finding(severity="critical")]),
            url="https://alerts",
            extra_headers={WEBHOOK_SIG_HEADER: "forged"},
        )


@requires_vendor_key
def test_webhook_alert_skips_when_no_finding_meets_threshold(licensed: Path) -> None:
    captured: list[dict[str, Any]] = []
    with _capturing_client(captured) as client:
        result = alert_to_webhook(
            _report(findings=[_finding(severity="low")]),
            url="https://alerts",
            min_severity="high",
            client=client,
        )
    assert result.findings_alerted == 0
    assert captured == []


# -- Gate behaviour ------------------------------------------------------


def test_alerts_block_without_license(monkeypatch: pytest.MonkeyPatch) -> None:
    def _raise() -> Any:
        raise LicenseMissingError("no license")

    monkeypatch.setattr("airsdk_pro.gate.load_license", _raise)
    with pytest.raises(LicenseMissingError):
        alert_to_slack(_report(), webhook_url="https://h")


@requires_vendor_key
def test_alerts_block_when_feature_not_in_license(
    tmp_path: Path,
    issue_token: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    token = issue_token(
        email="other@vindicara.io",
        tier="individual",
        features=("siem-integrations",),
    )
    license_path = tmp_path / "license.json"
    install_license(token, path=license_path)
    monkeypatch.setattr(
        "airsdk_pro.gate.load_license", lambda: load_license(license_path)
    )
    with pytest.raises(LicenseInvalidError):
        alert_to_slack(_report(), webhook_url="https://h")
