"""Shared constants for the premium detector surface."""
from __future__ import annotations

PREMIUM_DETECTORS_FEATURE = "premium-detectors"
"""License feature flag the premium detectors gate on."""

# Premium detectors that ship in this release. Used by `air detect-premium`
# to print accurate coverage info, and by Pro consumers that want to
# discover the surface programmatically.
PREMIUM_DETECTOR_IDS: tuple[tuple[str, str, str], ...] = (
    (
        "ASI04-PD",
        "Dependency Install Surface",
        "Tool invocation invokes a package manager or executes a remote shell pipe (pip/npm/cargo/curl|bash).",
    ),
    (
        "ASI04-TM",
        "Tool Manifest Drift",
        "The same tool name appears with significantly diverging argument schemas across the chain (possible manifest substitution).",
    ),
    (
        "ASI04-USF",
        "Untrusted Source Fetch",
        "Tool args contain URLs that fetch executable content from untrusted hosts (raw GitHub, gists, pastebins, ngrok, lhr.life).",
    ),
)
