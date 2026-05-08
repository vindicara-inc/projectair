"""SIEM push helpers (Pro).

Thin HTTPS push helpers that take a Project AIR ``ForensicReport`` and
deliver each detector finding as a structured event to a customer-owned
SIEM. The OSS package already exports CEF (one event per finding) to
disk; these helpers eliminate the "scrape the file from disk and POST
it" glue that customers would otherwise write themselves.

Vendors covered in this module:

- **Datadog** Logs API v2 (``push_to_datadog``)
- **Splunk** HTTP Event Collector (``push_to_splunk_hec``)
- **Sumo Logic** Hosted HTTP Source (``push_to_sumo``)
- **Microsoft Sentinel** via Azure Log Analytics Data Collector API
  (``push_to_sentinel``)

Each function is gated behind the ``siem-integrations`` Pro feature
flag. The helpers do not open inbound network listeners, do not store
credentials, and never phone home to Vindicara: every push goes
directly from the customer's process to the customer's SIEM endpoint.
"""
from __future__ import annotations

from airsdk_pro.siem.datadog import DEFAULT_DATADOG_SITE, push_to_datadog
from airsdk_pro.siem.sentinel import push_to_sentinel
from airsdk_pro.siem.splunk import push_to_splunk_hec
from airsdk_pro.siem.sumo import push_to_sumo
from airsdk_pro.siem.types import (
    SIEM_INTEGRATIONS_FEATURE,
    SiemConfigError,
    SiemPushError,
    SiemPushResult,
)

__all__ = [
    "DEFAULT_DATADOG_SITE",
    "SIEM_INTEGRATIONS_FEATURE",
    "SiemConfigError",
    "SiemPushError",
    "SiemPushResult",
    "push_to_datadog",
    "push_to_sentinel",
    "push_to_splunk_hec",
    "push_to_sumo",
]
