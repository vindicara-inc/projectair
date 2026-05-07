"""Tests for the Sigstore Rekor client. Live test gated by ``-m network``."""
from __future__ import annotations

import json
import urllib.error
from unittest.mock import MagicMock, patch

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from airsdk.anchoring.exceptions import (
    RekorEntryRejectedError,
    RekorRateLimitedError,
    RekorUnreachableError,
)
from airsdk.anchoring.rekor import RekorClient


def _client() -> RekorClient:
    return RekorClient(signing_key=Ed25519PrivateKey.generate(), rekor_url="https://fake.rekor")


def test_rejects_invalid_url_scheme() -> None:
    with pytest.raises(ValueError, match="http"):
        RekorClient(signing_key=Ed25519PrivateKey.generate(), rekor_url="ftp://x")


def test_rejects_wrong_digest_size() -> None:
    client = _client()
    with pytest.raises(ValueError, match="32 bytes"):
        client.anchor(b"too-short")


def test_unreachable_raises() -> None:
    client = _client()
    err = urllib.error.URLError("DNS failure")
    with (
        patch("airsdk.anchoring.rekor.urllib.request.urlopen", side_effect=err),
        pytest.raises(RekorUnreachableError),
    ):
        client.anchor(b"x" * 32)


def test_429_after_retries_raises_rate_limited() -> None:
    client = _client()
    http_err = urllib.error.HTTPError(
        url="https://fake.rekor/api/v1/log/entries",
        code=429,
        msg="rate limited",
        hdrs=None,  # type: ignore[arg-type]
        fp=None,
    )
    with (
        patch("airsdk.anchoring.rekor.urllib.request.urlopen", side_effect=http_err),
        patch("airsdk.anchoring.rekor.time.sleep"),
        pytest.raises(RekorRateLimitedError),
    ):
        client.anchor(b"x" * 32)


def test_4xx_other_than_429_raises_entry_rejected() -> None:
    client = _client()
    http_err = urllib.error.HTTPError(
        url="https://fake.rekor/api/v1/log/entries",
        code=400,
        msg="bad request",
        hdrs=None,  # type: ignore[arg-type]
        fp=None,
    )
    http_err.read = MagicMock(return_value=b"bad input")  # type: ignore[method-assign]
    with (
        patch("airsdk.anchoring.rekor.urllib.request.urlopen", side_effect=http_err),
        pytest.raises(RekorEntryRejectedError),
    ):
        client.anchor(b"x" * 32)


def test_hashedrekord_request_shape() -> None:
    client = _client()
    body = client._build_hashedrekord(
        digest=b"\xaa" * 32,
        signature=b"\xff" * 64,
    )
    assert body["kind"] == "hashedrekord"
    assert body["apiVersion"] == "0.0.1"
    assert body["spec"]["data"]["hash"]["algorithm"] == "sha256"
    assert body["spec"]["data"]["hash"]["value"] == "aa" * 32
    assert "publicKey" in body["spec"]["signature"]
    # Round-trip through JSON to confirm the body is serializable.
    json.dumps(body)


def test_verify_rejects_wrong_digest_size() -> None:
    from airsdk.types import RekorAnchor as _Anchor

    client = _client()
    anchor = _Anchor(
        log_index=1,
        uuid="x",
        integrated_time=0,
        log_id="00",
        inclusion_proof={},
        rekor_url="https://fake.rekor",
    )
    with pytest.raises(ValueError, match="32 bytes"):
        client.verify(anchor, b"too-short")


def test_verify_with_empty_inclusion_proof_raises() -> None:
    """A stored anchor whose inclusion_proof can't be parsed by sigstore-python
    must raise RekorProofInvalidError rather than report success."""
    from airsdk.anchoring.exceptions import RekorProofInvalidError
    from airsdk.types import RekorAnchor as _Anchor

    client = _client()
    anchor = _Anchor(
        log_index=1,
        uuid="x",
        integrated_time=0,
        log_id="00",
        inclusion_proof={},
        rekor_url="https://fake.rekor",
    )
    with pytest.raises(RekorProofInvalidError):
        client.verify(anchor, b"\x00" * 32)


def test_default_url_is_public_rekor() -> None:
    rc = RekorClient(signing_key=Ed25519PrivateKey.generate())
    assert rc.rekor_url == "https://rekor.sigstore.dev"
