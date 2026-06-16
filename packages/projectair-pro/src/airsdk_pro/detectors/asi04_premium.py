"""Premium ASI04 (Agentic Supply Chain Vulnerabilities) sub-detectors.

The OSS detector ``detect_mcp_supply_chain_risk`` covers MCP-naming
patterns only. This module adds three sub-detectors under the same
OWASP category, each gated behind the ``premium-detectors`` Pro
feature flag:

- **ASI04-PD Dependency Install Surface** — flags tool calls that
  invoke a package manager or execute a remote shell pipe.
- **ASI04-TM Tool Manifest Drift** — flags the same ``tool_name``
  appearing with significantly diverging argument schemas across the
  chain (signal of mid-session manifest substitution).
- **ASI04-USF Untrusted Source Fetch** — flags tool args that fetch
  executable content from sources commonly used to bypass dependency
  review (raw GitHub, gists, pastebins, ngrok / localhost.run tunnels).

These are heuristics on the signed chain. They emit ``Finding``
objects in the same shape as OSS detectors so existing reports and
exports consume them unchanged.
"""
from __future__ import annotations

import json
import re
from typing import Any

from airsdk.types import AgDRRecord, Finding, StepKind

from airsdk_pro.detectors.types import PREMIUM_DETECTORS_FEATURE
from airsdk_pro.gate import requires_pro

# ASI04-PD patterns: package managers + shell-pipe-from-network
INSTALL_TOOL_PATTERNS = (
    re.compile(r"\b(?:pip|pip3|pipx)\s+install\b"),
    re.compile(r"\bnpm\s+(?:i|install|add)\b"),
    re.compile(r"\bpnpm\s+(?:i|install|add)\b"),
    re.compile(r"\byarn\s+(?:add|install)\b"),
    re.compile(r"\bgem\s+install\b"),
    re.compile(r"\bcargo\s+install\b"),
    re.compile(r"\bgo\s+install\b"),
    re.compile(r"\bapt(?:-get)?\s+install\b"),
    re.compile(r"\byum\s+install\b"),
    re.compile(r"\bbrew\s+install\b"),
    re.compile(r"\bdnf\s+install\b"),
    re.compile(r"\bcurl\s+[^|]+\|\s*(?:bash|sh|zsh|python\d?)\b"),
    re.compile(r"\bwget\s+[^|]+\|\s*(?:bash|sh|zsh|python\d?)\b"),
)

# ASI04-USF patterns: hosts commonly used to bypass dependency review
UNTRUSTED_HOST_PATTERNS = (
    re.compile(r"https?://raw\.githubusercontent\.com/"),
    re.compile(r"https?://gist\.githubusercontent\.com/"),
    re.compile(r"https?://gist\.github\.com/[^/\s]+/[a-f0-9]+/raw"),
    re.compile(r"https?://[a-z0-9\-]+\.ngrok\.(?:io|app|dev)"),
    re.compile(r"https?://[a-z0-9\-]+\.lhr\.life"),
    re.compile(r"https?://[a-z0-9\-]+\.serveo\.net"),
    re.compile(r"https?://(?:pastebin|hastebin|paste\.ee|paste\.rs)\.com?/raw"),
    re.compile(r"https?://transfer\.sh/"),
    re.compile(r"https?://0x0\.st/"),
)

# ASI04-TM threshold: a previously-stable tool that gains new keys mid-chain
# is suspicious. We require at least 2 prior calls with a stable schema
# before flagging a third call that adds keys.
MANIFEST_DRIFT_MIN_PRIOR_CALLS = 2


@requires_pro(feature=PREMIUM_DETECTORS_FEATURE)
def detect_supply_chain_premium(records: list[AgDRRecord]) -> list[Finding]:
    """Run all three premium ASI04 sub-detectors over ``records``.

    Returns a flat list of ``Finding`` objects with detector_id values
    ``ASI04-PD`` / ``ASI04-TM`` / ``ASI04-USF``. Severity is per
    sub-detector; see each ``_detect_*`` function's docstring.
    """
    findings: list[Finding] = []
    findings.extend(_detect_install_surface(records))
    findings.extend(_detect_manifest_drift(records))
    findings.extend(_detect_untrusted_source_fetch(records))
    return findings


@requires_pro(feature=PREMIUM_DETECTORS_FEATURE)
def run_premium_detectors(records: list[AgDRRecord]) -> list[Finding]:
    """Convenience wrapper. Runs every premium detector this release ships.

    Today that's just ``detect_supply_chain_premium``; later releases add
    more sub-detectors under other OWASP categories without breaking
    callers of this entrypoint.
    """
    return detect_supply_chain_premium(records)


def _detect_install_surface(records: list[AgDRRecord]) -> list[Finding]:
    """ASI04-PD: tool calls that invoke a package manager or remote shell pipe."""
    findings: list[Finding] = []
    for index, record in enumerate(records):
        if record.kind != StepKind.TOOL_START:
            continue
        haystack = _searchable_text(record)
        for pattern in INSTALL_TOOL_PATTERNS:
            match = pattern.search(haystack)
            if match:
                findings.append(
                    Finding(
                        detector_id="ASI04-PD",
                        title="Agentic Supply Chain: Dependency Install Surface",
                        severity="high",
                        step_id=record.step_id,
                        step_index=index,
                        description=(
                            f"Tool call invokes a package manager or remote shell pipe "
                            f"(matched: {match.group(0)!r}). Cross-reference against your "
                            f"approved-dependency manifest before treating this as legitimate."
                        ),
                    )
                )
                break
    return findings


def _detect_manifest_drift(records: list[AgDRRecord]) -> list[Finding]:
    """ASI04-TM: same tool_name appearing with diverging arg schemas mid-chain."""
    findings: list[Finding] = []
    seen_keys: dict[str, set[str]] = {}
    call_count: dict[str, int] = {}
    for index, record in enumerate(records):
        if record.kind != StepKind.TOOL_START or not record.payload.tool_name:
            continue
        name = record.payload.tool_name
        args = record.payload.tool_args or {}
        keys = set(args.keys())
        prior_keys = seen_keys.get(name)
        prior_calls = call_count.get(name, 0)

        if (
            prior_keys is not None
            and prior_calls >= MANIFEST_DRIFT_MIN_PRIOR_CALLS
            and not keys.issubset(prior_keys)
            and keys != prior_keys
        ):
            new_keys = keys - prior_keys
            findings.append(
                Finding(
                    detector_id="ASI04-TM",
                    title="Agentic Supply Chain: Tool Manifest Drift",
                    severity="medium",
                    step_id=record.step_id,
                    step_index=index,
                    description=(
                        f"Tool `{name}` previously stable across {prior_calls} call(s) "
                        f"with keys {sorted(prior_keys)} now invoked with new keys "
                        f"{sorted(new_keys)}. Possible manifest substitution; verify "
                        f"the tool's manifest hash has not changed mid-session."
                    ),
                )
            )
        seen_keys[name] = (prior_keys or set()) | keys
        call_count[name] = prior_calls + 1
    return findings


def _detect_untrusted_source_fetch(records: list[AgDRRecord]) -> list[Finding]:
    """ASI04-USF: tool args fetching executable content from review-bypassing hosts."""
    findings: list[Finding] = []
    for index, record in enumerate(records):
        if record.kind != StepKind.TOOL_START:
            continue
        haystack = _searchable_text(record)
        for pattern in UNTRUSTED_HOST_PATTERNS:
            match = pattern.search(haystack)
            if match:
                findings.append(
                    Finding(
                        detector_id="ASI04-USF",
                        title="Agentic Supply Chain: Untrusted Source Fetch",
                        severity="high",
                        step_id=record.step_id,
                        step_index=index,
                        description=(
                            f"Tool args fetch from a host pattern that bypasses normal "
                            f"dependency review ({match.group(0)!r}). Treat the fetched "
                            f"content as untrusted regardless of the calling tool."
                        ),
                    )
                )
                break
    return findings


def _searchable_text(record: AgDRRecord) -> str:
    """Concatenate the fields a supply-chain detector looks at into one string."""
    parts: list[str] = []
    if record.payload.tool_name:
        parts.append(record.payload.tool_name)
    if record.payload.tool_args:
        try:
            parts.append(json.dumps(record.payload.tool_args, separators=(",", ":")))
        except (TypeError, ValueError):
            parts.append(_safe_repr(record.payload.tool_args))
    if record.payload.prompt:
        parts.append(record.payload.prompt)
    return " ".join(parts)


def _safe_repr(value: Any) -> str:
    try:
        return repr(value)
    except Exception:
        return ""
