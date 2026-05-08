"""push_chain_to_air_cloud (Pro) — hosted ingest client."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import httpx
import pytest
from airsdk.types import AgDRPayload, AgDRRecord, StepKind

from _helpers import requires_vendor_key
from airsdk_pro.cloud import (
    AIR_CLOUD_CLIENT_FEATURE,
    DEFAULT_BASE_URL,
    CloudConfigError,
    CloudPushError,
    push_chain_to_air_cloud,
)
from airsdk_pro.license import (
    LicenseInvalidError,
    LicenseMissingError,
    install_license,
    load_license,
)

DUMMY_HASH = "0" * 64
DUMMY_SIG = "aa" * 64
DUMMY_KEY = "bb" * 32


def _record(step_id: str = "step-1") -> AgDRRecord:
    return AgDRRecord(
        step_id=step_id,
        timestamp="2026-04-21T12:00:00Z",
        kind=StepKind.LLM_START,
        payload=AgDRPayload.model_validate({}),
        prev_hash=DUMMY_HASH,
        content_hash=DUMMY_HASH,
        signature=DUMMY_SIG,
        signer_key=DUMMY_KEY,
    )


@pytest.fixture
def licensed(
    tmp_path: Path,
    issue_token: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> Path:
    token = issue_token(
        email="cloud-tests@vindicara.io",
        tier="individual",
        features=(AIR_CLOUD_CLIENT_FEATURE,),
    )
    license_path = tmp_path / "license.json"
    install_license(token, path=license_path)
    monkeypatch.setattr(
        "airsdk_pro.gate.load_license", lambda: load_license(license_path)
    )
    return license_path


def _capturing_client(captured: dict[str, Any], status_code: int = 200) -> httpx.Client:
    def handler(request: httpx.Request) -> httpx.Response:
        captured["url"] = str(request.url)
        captured["method"] = request.method
        captured["headers"] = dict(request.headers)
        captured["body"] = request.content
        return httpx.Response(status_code, json={"workspace_id": "acme", "stored": 2})
    return httpx.Client(transport=httpx.MockTransport(handler))


@requires_vendor_key
def test_air_cloud_targets_default_base_url(licensed: Path) -> None:
    captured: dict[str, Any] = {}
    records = [_record("a"), _record("b")]
    with _capturing_client(captured) as client:
        result = push_chain_to_air_cloud(records, api_key="air_test", client=client)
    assert result.target == "air_cloud"
    assert result.records_sent == 2
    assert result.endpoint == f"{DEFAULT_BASE_URL}/v1/capsules/bulk"
    assert captured["url"] == f"{DEFAULT_BASE_URL}/v1/capsules/bulk"
    assert captured["headers"]["x-api-key"] == "air_test"
    assert captured["headers"]["content-type"] == "application/x-ndjson"


@requires_vendor_key
def test_air_cloud_custom_base_url(licensed: Path) -> None:
    captured: dict[str, Any] = {}
    with _capturing_client(captured) as client:
        push_chain_to_air_cloud(
            [_record()],
            api_key="air_test",
            base_url="https://eu.cloud.vindicara.io/",
            client=client,
        )
    assert captured["url"] == "https://eu.cloud.vindicara.io/v1/capsules/bulk"


@requires_vendor_key
def test_air_cloud_body_is_ndjson_one_record_per_line(licensed: Path) -> None:
    captured: dict[str, Any] = {}
    records = [_record("a"), _record("b"), _record("c")]
    with _capturing_client(captured) as client:
        push_chain_to_air_cloud(records, api_key="air_test", client=client)
    body = captured["body"].decode("utf-8")
    lines = [line for line in body.split("\n") if line]
    assert len(lines) == 3
    parsed = [json.loads(line) for line in lines]
    assert [p["step_id"] for p in parsed] == ["a", "b", "c"]


@requires_vendor_key
def test_air_cloud_empty_records_skips_request(licensed: Path) -> None:
    captured: dict[str, Any] = {}
    with _capturing_client(captured) as client:
        result = push_chain_to_air_cloud([], api_key="air_test", client=client)
    assert result.records_sent == 0
    assert "url" not in captured  # no HTTP call


@requires_vendor_key
def test_air_cloud_missing_api_key_raises(licensed: Path) -> None:
    with pytest.raises(CloudConfigError):
        push_chain_to_air_cloud([_record()], api_key="")


@requires_vendor_key
def test_air_cloud_missing_base_url_raises(licensed: Path) -> None:
    with pytest.raises(CloudConfigError):
        push_chain_to_air_cloud([_record()], api_key="air_test", base_url="")


@requires_vendor_key
def test_air_cloud_non_2xx_raises(licensed: Path) -> None:
    captured: dict[str, Any] = {}
    with (
        _capturing_client(captured, status_code=401) as client,
        pytest.raises(CloudPushError) as exc_info,
    ):
        push_chain_to_air_cloud([_record()], api_key="air_test", client=client)
    assert exc_info.value.status_code == 401


def test_air_cloud_blocks_without_license(monkeypatch: pytest.MonkeyPatch) -> None:
    def _raise() -> Any:
        raise LicenseMissingError("no license")

    monkeypatch.setattr("airsdk_pro.gate.load_license", _raise)
    with pytest.raises(LicenseMissingError):
        push_chain_to_air_cloud([_record()], api_key="air_test")


@requires_vendor_key
def test_air_cloud_blocks_when_feature_not_in_license(
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
        push_chain_to_air_cloud([_record()], api_key="air_test")
