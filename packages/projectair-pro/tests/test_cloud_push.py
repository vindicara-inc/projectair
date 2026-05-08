"""AIR Cloud client v0 push helpers (webhook + S3)."""
from __future__ import annotations

import hashlib
import hmac
import json
from pathlib import Path
from typing import Any

import httpx
import pytest
from airsdk.types import AgDRPayload, AgDRRecord, StepKind

from _helpers import requires_vendor_key
from airsdk_pro.cloud import (
    AIR_CLOUD_CLIENT_FEATURE,
    CloudConfigError,
    CloudPushError,
    push_chain_to_s3,
    push_chain_to_webhook,
)
from airsdk_pro.cloud.webhook import SIGNATURE_HEADER
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
        return httpx.Response(status_code)
    return httpx.Client(transport=httpx.MockTransport(handler))


# -- Webhook -------------------------------------------------------------


@requires_vendor_key
def test_webhook_pushes_jsonl_one_line_per_record(licensed: Path) -> None:
    captured: dict[str, Any] = {}
    records = [_record("a"), _record("b"), _record("c")]
    with _capturing_client(captured) as client:
        result = push_chain_to_webhook(records, url="https://hooks.example.com/air", client=client)
    assert result.target == "webhook"
    assert result.records_sent == 3
    assert result.endpoint == "https://hooks.example.com/air"
    assert captured["headers"]["content-type"] == "application/x-ndjson"
    body_text = captured["body"].decode("utf-8")
    lines = [line for line in body_text.split("\n") if line]
    assert len(lines) == 3
    parsed = [json.loads(line) for line in lines]
    assert [p["step_id"] for p in parsed] == ["a", "b", "c"]


@requires_vendor_key
def test_webhook_signs_body_with_hmac_when_secret_is_set(licensed: Path) -> None:
    captured: dict[str, Any] = {}
    secret = "shared-secret-32-bytes-of-pure-test"  # noqa: S105
    with _capturing_client(captured) as client:
        push_chain_to_webhook([_record()], url="https://h/air", secret=secret, client=client)
    sig_header = captured["headers"][SIGNATURE_HEADER.lower()]
    assert sig_header.startswith("sha256=")
    expected = hmac.new(secret.encode("utf-8"), captured["body"], hashlib.sha256).hexdigest()
    assert sig_header == f"sha256={expected}"


@requires_vendor_key
def test_webhook_no_signature_header_without_secret(licensed: Path) -> None:
    captured: dict[str, Any] = {}
    with _capturing_client(captured) as client:
        push_chain_to_webhook([_record()], url="https://h/air", client=client)
    assert SIGNATURE_HEADER.lower() not in captured["headers"]


@requires_vendor_key
def test_webhook_extra_headers_merged(licensed: Path) -> None:
    captured: dict[str, Any] = {}
    with _capturing_client(captured) as client:
        push_chain_to_webhook(
            [_record()],
            url="https://h/air",
            extra_headers={"X-Tenant-Id": "tenant-001"},
            client=client,
        )
    assert captured["headers"]["x-tenant-id"] == "tenant-001"


@requires_vendor_key
def test_webhook_extra_headers_cannot_override_content_type(licensed: Path) -> None:
    with pytest.raises(CloudConfigError):
        push_chain_to_webhook(
            [_record()],
            url="https://h/air",
            extra_headers={"Content-Type": "text/plain"},
        )


@requires_vendor_key
def test_webhook_extra_headers_cannot_override_signature(licensed: Path) -> None:
    with pytest.raises(CloudConfigError):
        push_chain_to_webhook(
            [_record()],
            url="https://h/air",
            extra_headers={SIGNATURE_HEADER: "forged"},
        )


@requires_vendor_key
def test_webhook_empty_chain_skips_request(licensed: Path) -> None:
    captured: dict[str, Any] = {}
    with _capturing_client(captured) as client:
        result = push_chain_to_webhook([], url="https://h/air", client=client)
    assert result.records_sent == 0
    assert result.bytes_sent == 0
    assert "url" not in captured  # no HTTP call was made


@requires_vendor_key
def test_webhook_missing_url_raises_config_error(licensed: Path) -> None:
    with pytest.raises(CloudConfigError):
        push_chain_to_webhook([_record()], url="")


@requires_vendor_key
def test_webhook_non_2xx_raises_push_error(licensed: Path) -> None:
    captured: dict[str, Any] = {}
    with (
        _capturing_client(captured, status_code=503) as client,
        pytest.raises(CloudPushError) as exc_info,
    ):
        push_chain_to_webhook([_record()], url="https://h/air", client=client)
    assert exc_info.value.status_code == 503


# -- S3 ------------------------------------------------------------------


class _FakeS3Client:
    """In-memory stand-in for boto3 S3 client used by the S3 push tests."""

    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []

    def put_object(self, **kwargs: Any) -> dict[str, Any]:
        self.calls.append(kwargs)
        return {"ETag": '"deadbeef"'}


@requires_vendor_key
def test_s3_push_invokes_put_object_with_correct_payload(licensed: Path) -> None:
    fake = _FakeS3Client()
    records = [_record("a"), _record("b")]
    result = push_chain_to_s3(records, bucket="my-bucket", key="chains/2026-q2.jsonl", client=fake)
    assert result.target == "s3"
    assert result.records_sent == 2
    assert result.endpoint == "s3://my-bucket/chains/2026-q2.jsonl"
    assert len(fake.calls) == 1
    call = fake.calls[0]
    assert call["Bucket"] == "my-bucket"
    assert call["Key"] == "chains/2026-q2.jsonl"
    assert call["ContentType"] == "application/x-ndjson"
    assert call["ServerSideEncryption"] == "AES256"
    body_lines = call["Body"].decode("utf-8").strip().split("\n")
    assert len(body_lines) == 2


@requires_vendor_key
def test_s3_push_propagates_metadata(licensed: Path) -> None:
    fake = _FakeS3Client()
    push_chain_to_s3(
        [_record()],
        bucket="b",
        key="k",
        metadata={"system_id": "sys-1", "tenant": "acme"},
        client=fake,
    )
    assert fake.calls[0]["Metadata"] == {"system_id": "sys-1", "tenant": "acme"}


@requires_vendor_key
def test_s3_push_can_disable_server_side_encryption(licensed: Path) -> None:
    fake = _FakeS3Client()
    push_chain_to_s3([_record()], bucket="b", key="k", sse=None, client=fake)
    assert "ServerSideEncryption" not in fake.calls[0]


@requires_vendor_key
def test_s3_push_empty_chain_skips_put(licensed: Path) -> None:
    fake = _FakeS3Client()
    result = push_chain_to_s3([], bucket="b", key="k", client=fake)
    assert result.records_sent == 0
    assert fake.calls == []


@requires_vendor_key
def test_s3_push_missing_bucket_raises_config_error(licensed: Path) -> None:
    with pytest.raises(CloudConfigError):
        push_chain_to_s3([_record()], bucket="", key="k")


@requires_vendor_key
def test_s3_push_missing_key_raises_config_error(licensed: Path) -> None:
    with pytest.raises(CloudConfigError):
        push_chain_to_s3([_record()], bucket="b", key="")


@requires_vendor_key
def test_s3_push_without_boto3_raises_helpful_config_error(
    licensed: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """If boto3 import fails (no [s3] extra), surface a clear install message."""
    import builtins

    real_import = builtins.__import__

    def fake_import(name: str, globals: Any = None, locals: Any = None, fromlist: Any = (), level: int = 0) -> Any:  # noqa: A002
        if name == "boto3":
            raise ImportError("No module named 'boto3'")
        return real_import(name, globals, locals, fromlist, level)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    with pytest.raises(CloudConfigError, match=r"\[s3\]"):
        push_chain_to_s3([_record()], bucket="b", key="k")


# -- Gate behaviour ------------------------------------------------------


def test_webhook_blocks_without_license(monkeypatch: pytest.MonkeyPatch) -> None:
    def _raise() -> Any:
        raise LicenseMissingError("no license")

    monkeypatch.setattr("airsdk_pro.gate.load_license", _raise)
    with pytest.raises(LicenseMissingError):
        push_chain_to_webhook([_record()], url="https://h")


@requires_vendor_key
def test_webhook_blocks_when_feature_not_in_license(
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
        push_chain_to_webhook([_record()], url="https://h")


def test_s3_blocks_without_license(monkeypatch: pytest.MonkeyPatch) -> None:
    def _raise() -> Any:
        raise LicenseMissingError("no license")

    monkeypatch.setattr("airsdk_pro.gate.load_license", _raise)
    with pytest.raises(LicenseMissingError):
        push_chain_to_s3([_record()], bucket="b", key="k")
