"""AIR Cloud client (Pro): push signed Intent Capsule chains to durable storage.

This is the "AIR Cloud client SDK" line on the public pricing page,
implemented today as direct push helpers that target storage the
**customer** owns: an HTTPS webhook endpoint or an S3 bucket. The
hosted multi-tenant Vindicara ingest service is a follow-on release;
once it ships, the same client surface gets a default endpoint and
authentication path, but the wire format remains stable.

Why customer-owned storage first:
- It makes "AIR Cloud client" a real shipping feature now, not a stub.
- It works air-gapped and in regulated tenants without any Vindicara
  control plane in the data path.
- It defers the multi-tenant question (auth, billing, retention,
  data residency) until the hosted service is ready, instead of locking
  customers into a half-built ingest API.

All entry points are gated behind the ``air-cloud-client`` Pro feature
flag.
"""
from __future__ import annotations

from airsdk_pro.cloud.air_cloud import (
    DEFAULT_BASE_URL,
    push_chain_to_air_cloud,
)
from airsdk_pro.cloud.s3 import push_chain_to_s3
from airsdk_pro.cloud.types import (
    AIR_CLOUD_CLIENT_FEATURE,
    CloudConfigError,
    CloudPushError,
    CloudPushResult,
)
from airsdk_pro.cloud.webhook import push_chain_to_webhook

__all__ = [
    "AIR_CLOUD_CLIENT_FEATURE",
    "DEFAULT_BASE_URL",
    "CloudConfigError",
    "CloudPushError",
    "CloudPushResult",
    "push_chain_to_air_cloud",
    "push_chain_to_s3",
    "push_chain_to_webhook",
]
