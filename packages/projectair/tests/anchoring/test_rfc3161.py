"""Tests for the RFC 3161 client. Live FreeTSA test is gated by ``-m network``."""
from __future__ import annotations

import logging
import urllib.error
from unittest.mock import MagicMock, patch

import pytest

from airsdk.anchoring.exceptions import (
    TSARateLimitedError,
    TSAResponseInvalidError,
    TSAUnreachableError,
)
from airsdk.anchoring.rfc3161 import RFC3161Client


def test_unreachable_raises_tsa_unreachable() -> None:
    client = RFC3161Client(tsa_url="http://nonexistent.invalid", timeout_seconds=0.5)
    err = urllib.error.URLError("fake DNS failure")
    with (
        patch("airsdk.anchoring.rfc3161.urllib.request.urlopen", side_effect=err),
        pytest.raises(TSAUnreachableError),
    ):
        client.anchor(b"x" * 32)


def test_response_with_wrong_content_type_raises() -> None:
    fake_response = MagicMock()
    fake_response.headers = {"Content-Type": "text/html"}
    fake_response.read.return_value = b""
    fake_response.__enter__ = MagicMock(return_value=fake_response)
    fake_response.__exit__ = MagicMock(return_value=False)

    client = RFC3161Client(tsa_url="http://fake/tsr")
    with (
        patch("airsdk.anchoring.rfc3161.urllib.request.urlopen", return_value=fake_response),
        pytest.raises(TSAResponseInvalidError, match="Content-Type"),
    ):
        client.anchor(b"x" * 32)


def test_verify_with_corrupt_token_raises() -> None:
    """A garbled timestamp_token_b64 must raise rather than silently fail open."""
    from airsdk.anchoring.exceptions import TSAResponseInvalidError
    from airsdk.types import RFC3161Anchor as _Anchor

    bad = _Anchor(
        tsa_url="https://fake/tsr",
        timestamp_token_b64="QUFBQUFBQUE=",  # noqa: S106 - test stub: 8 'A' bytes, not a valid token
        timestamp_iso="2026-01-01T00:00:00Z",
        tsa_certificate_chain_pem=[],
    )
    client = RFC3161Client()
    with pytest.raises(TSAResponseInvalidError):
        client.verify(bad, b"\x00" * 32)


def test_default_construction_uses_freetsa() -> None:
    client = RFC3161Client()
    assert "freetsa" in client.tsa_url


def test_429_raises_rate_limited_and_logs_warning(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """A 429 from the TSA must surface as TSARateLimitedError plus a WARNING.

    Public TSAs throttle aggressive callers (default 10s cadence translates
    to ~360 req/hr per process; 10 instances on FreeTSA can trip the limit).
    The orchestrator's "tsa_failed" status alone hides the cause; the
    warning log is what an operator running a fleet sees first.
    """
    client = RFC3161Client(tsa_url="http://fake/tsr")
    http_err = urllib.error.HTTPError(
        url="http://fake/tsr",
        code=429,
        msg="Too Many Requests",
        hdrs=None,  # type: ignore[arg-type]
        fp=None,
    )
    caplog.set_level(logging.WARNING, logger="airsdk.anchoring.rfc3161")
    with (
        patch("airsdk.anchoring.rfc3161.urllib.request.urlopen", side_effect=http_err),
        pytest.raises(TSARateLimitedError),
    ):
        client.anchor(b"x" * 32)
    assert any("429" in r.message and "rate-limit" in r.message.lower() for r in caplog.records)


def test_non_429_http_error_raises_unreachable() -> None:
    """500 / 503 should still classify as unreachable, distinct from 429."""
    client = RFC3161Client(tsa_url="http://fake/tsr")
    http_err = urllib.error.HTTPError(
        url="http://fake/tsr",
        code=503,
        msg="Service Unavailable",
        hdrs=None,  # type: ignore[arg-type]
        fp=None,
    )
    with (
        patch("airsdk.anchoring.rfc3161.urllib.request.urlopen", side_effect=http_err),
        pytest.raises(TSAUnreachableError),
    ):
        client.anchor(b"x" * 32)


@pytest.mark.network
def test_freetsa_live_anchor_and_verify() -> None:
    """Round-trip against the real FreeTSA service. Requires outbound HTTPS."""
    client = RFC3161Client()
    chain_root = b"\x00" * 32
    anchor = client.anchor(chain_root)
    assert anchor.timestamp_iso
    assert anchor.timestamp_token_b64
    assert client.verify(anchor, chain_root) is True
