"""SV-NET: network egress to undeclared destinations."""
from __future__ import annotations

import re
from typing import Final

from airsdk.types import AgDRRecord, IntentSpec, StepKind
from airsdk.verification.types import Violation

_NETWORK_TOOLS: Final[frozenset[str]] = frozenset({
    "http_post", "http_get", "http_put", "http_delete", "http_patch",
    "http_request", "fetch", "curl", "wget", "requests_get", "requests_post",
    "api_call", "send_request", "web_request",
})

_URL_PATTERN: Final[re.Pattern[str]] = re.compile(r"https?://([^/:\s]+)")


def _is_network_tool(tool_name: str) -> bool:
    lower = tool_name.lower()
    return lower in _NETWORK_TOOLS or "http" in lower or "request" in lower


def _extract_destination(record: AgDRRecord) -> str | None:
    args = record.payload.tool_args or {}
    for key in ("url", "endpoint", "uri", "href", "destination"):
        val = args.get(key)
        if isinstance(val, str):
            match = _URL_PATTERN.search(val)
            if match:
                return match.group(1)
            return val
    for val in args.values():
        if isinstance(val, str):
            match = _URL_PATTERN.search(val)
            if match:
                return match.group(1)
    return None


def check_network(
    records: list[AgDRRecord],
    intent_spec: IntentSpec | None,
) -> list[Violation]:
    allowed = set(intent_spec.allowed_network) if intent_spec else set()
    violations: list[Violation] = []

    for idx, record in enumerate(records):
        if record.kind != StepKind.TOOL_START:
            continue
        tool_name = record.payload.tool_name or ""
        if not _is_network_tool(tool_name):
            continue
        dest = _extract_destination(record)
        if dest and dest in allowed:
            continue

        is_post = "post" in tool_name.lower() or "put" in tool_name.lower()
        severity = "critical" if is_post else "high"
        dest_label = dest or "unknown"

        violations.append(Violation(
            check_id="SV-NET-01",
            title="Network egress to undeclared destination",
            severity=severity,
            step_index=idx,
            step_id=record.step_id,
            evidence=f"{tool_name}({dest_label})",
            expected="no network egress" if not allowed else f"allowed: {', '.join(sorted(allowed))}",
            actual=f"{tool_name} to {dest_label}",
        ))
    return violations
