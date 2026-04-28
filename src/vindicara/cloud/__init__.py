"""Vindicara AIR Cloud server-side ingestion engine.

Receives Signed Intent Capsules from OSS ``airsdk.recorder.AIRRecorder``
instances over HTTP, verifies them at the door, and persists them through
a swappable :class:`CapsuleStore` (in-memory for dev / tests, JSONL for
single-host deployments, DynamoDB for AWS production, etc.).
"""
from __future__ import annotations

from vindicara.cloud.capsule_store import (
    CapsuleStore,
    InMemoryCapsuleStore,
    JSONLCapsuleStore,
    StoredCapsule,
)

__all__ = [
    "CapsuleStore",
    "InMemoryCapsuleStore",
    "JSONLCapsuleStore",
    "StoredCapsule",
]
