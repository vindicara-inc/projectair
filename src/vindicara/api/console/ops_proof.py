"""Fetch live proof status from the public Vindicara ops chain manifest."""

from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.request
from dataclasses import dataclass

import structlog

logger = structlog.get_logger()

_DEFAULT_MANIFEST = (
    "https://vindicara-ops-chain-public-399827112476.s3.us-west-2.amazonaws.com"
    "/ops-chain/manifest.json"
)
_CACHE_TTL_SECONDS = 45.0


@dataclass(frozen=True)
class OpsManifest:
    latest_rekor_log_index: int
    rekor_url: str
    record_count: int = 0


@dataclass
class _CacheEntry:
    fetched_at: float
    manifest: OpsManifest | None
    error: str | None


_cache = _CacheEntry(fetched_at=0.0, manifest=None, error=None)


def _manifest_url() -> str:
    return os.environ.get("VINDICARA_OPS_CHAIN_MANIFEST_URL", _DEFAULT_MANIFEST)


def fetch_ops_manifest() -> tuple[OpsManifest | None, str | None]:
    """Return cached ops-chain manifest or fetch it from public S3."""
    now = time.monotonic()
    if now - _cache.fetched_at < _CACHE_TTL_SECONDS:
        return _cache.manifest, _cache.error

    url = _manifest_url()
    try:
        with urllib.request.urlopen(url, timeout=8) as response:  # noqa: S310
            payload = json.loads(response.read().decode("utf-8"))
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, KeyError) as exc:
        # Log full detail server-side; surface only a generic message. The exception
        # text can reveal internal URLs/hosts/structure and flows to the console
        # overview response, so it must not reach the client (CWE-209).
        logger.warning("ops_manifest.fetch_failed", url=url, error=str(exc))
        _cache.fetched_at = now
        _cache.manifest = None
        _cache.error = "ops chain manifest unavailable"
        return None, _cache.error

    manifest = OpsManifest(
        latest_rekor_log_index=int(payload.get("latest_rekor_log_index", 0)),
        rekor_url=str(payload.get("rekor_url", "https://search.sigstore.dev/")),
        record_count=int(payload.get("record_count", payload.get("records", 0))),
    )
    _cache.fetched_at = now
    _cache.manifest = manifest
    _cache.error = None
    return manifest, None


def proof_payload(manifest: OpsManifest | None, manifest_error: str | None) -> dict[str, object]:
    if manifest is None:
        return {
            "chainIntact": False,
            "records": 0,
            "tampered": 0,
            "signature": "ed25519",
            "lastAnchor": "unavailable",
            "rekorIndex": manifest_error or "manifest unavailable",
            "rekorUrl": "https://search.sigstore.dev/",
        }
    return {
        "chainIntact": True,
        "records": manifest.record_count,
        "tampered": 0,
        "signature": "ed25519",
        "lastAnchor": "live",
        "rekorIndex": str(manifest.latest_rekor_log_index),
        "rekorUrl": manifest.rekor_url,
    }
