"""SV-SCOPE: filesystem access outside declared scope."""
from __future__ import annotations

from pathlib import PurePosixPath

from airsdk.types import AgDRRecord, IntentSpec, StepKind
from airsdk.verification.types import Violation

_FILE_TOOLS: frozenset[str] = frozenset({
    "read_file", "write_file", "open_file", "create_file", "delete_file",
    "edit_file", "read", "write", "cat", "append_file",
})


def _is_file_tool(tool_name: str) -> bool:
    return tool_name.lower() in _FILE_TOOLS or "file" in tool_name.lower()


def _path_within_scope(path: str, allowed: list[str]) -> bool:
    resolved = PurePosixPath(path)
    for prefix in allowed:
        prefix_path = PurePosixPath(prefix)
        try:
            resolved.relative_to(prefix_path)
            return True
        except ValueError:
            continue
    return False


def check_scope(
    records: list[AgDRRecord],
    intent_spec: IntentSpec | None,
) -> list[Violation]:
    if not intent_spec or not intent_spec.allowed_paths:
        return []

    violations: list[Violation] = []
    allowed = intent_spec.allowed_paths

    for idx, record in enumerate(records):
        if record.kind != StepKind.TOOL_START:
            continue
        tool_name = record.payload.tool_name or ""
        if not _is_file_tool(tool_name):
            continue
        args = record.payload.tool_args or {}
        for key in ("path", "file", "filename", "filepath"):
            val = args.get(key)
            if isinstance(val, str) and not _path_within_scope(val, allowed):
                violations.append(Violation(
                    check_id="SV-SCOPE-01",
                    title="Filesystem access outside declared scope",
                    severity="high",
                    step_index=idx,
                    step_id=record.step_id,
                    evidence=f"{tool_name}({val})",
                    expected=f"paths within: {', '.join(allowed)}",
                    actual=f"accessed {val}",
                ))
    return violations
