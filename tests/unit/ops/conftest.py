"""Shared fixtures for ``vindicara.ops`` tests.

Public-chain redaction MACs every non-whitelisted field under a per-deployment
secret and fails closed when the secret is unset. Tests set a fixed dummy
secret so digests are deterministic within the suite.
"""
from __future__ import annotations

import pytest


@pytest.fixture(autouse=True)
def _redaction_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("VINDICARA_REDACTION_KEY", "test-redaction-secret-not-for-production")
