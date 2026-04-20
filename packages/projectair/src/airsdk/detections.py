"""OWASP Top 10 for Agentic Applications detectors.

Implemented as honest first-pass heuristics:
    - ASI01 Agent Goal Hijack
    - ASI02 Tool Misuse
    - ASI03 Prompt Injection
    - ASI05 Sensitive Data Exposure
    - ASI09 Supply Chain and MCP Risk

The rest are declared in ``UNIMPLEMENTED_DETECTORS`` so the CLI can surface
honest coverage state instead of silently pretending we checked them.
"""
from __future__ import annotations

import re

from airsdk.types import AgDRRecord, Finding, StepKind

STOPWORDS = frozenset({
    "a", "an", "and", "are", "as", "at", "be", "by", "do", "for", "from", "have",
    "he", "i", "in", "is", "it", "of", "on", "or", "please", "she", "that", "the",
    "their", "them", "they", "this", "to", "was", "were", "will", "with", "you",
    "your", "can", "could", "should", "would", "help", "me", "my", "us", "we",
})

SENSITIVE_TOOL_MARKERS = (
    "delete", "drop", "truncate", "exec", "shell", "sudo", "admin",
    "transfer", "wire", "refund", "migrate", "grant", "revoke",
    "send_email", "send_sms", "post_to", "publish",
)

GOAL_HIJACK_THRESHOLD = 0.15

# ASI02 dangerous-argument patterns. Defensible surface; expands over time.
DANGEROUS_ARG_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("shell metacharacters", re.compile(r"(?:\||;|&&|\$\(|`).*(?:rm|curl|wget|nc\s|bash|sh\s)", re.IGNORECASE)),
    ("path traversal", re.compile(r"\.\./|\.\.\\|/etc/passwd|/etc/shadow|%2e%2e", re.IGNORECASE)),
    ("unbounded SQL DELETE", re.compile(r"delete\s+from\s+\w+(?:\s*;|\s*$)", re.IGNORECASE)),
    ("unbounded SQL UPDATE", re.compile(r"update\s+\w+\s+set\s+[^;]*?(?:;|$)(?!.*where)", re.IGNORECASE | re.DOTALL)),
    ("SSRF-shaped URL", re.compile(r"https?://(?:127\.|0\.0\.0\.0|localhost|169\.254\.|10\.|192\.168\.|172\.(?:1[6-9]|2[0-9]|3[01])\.)", re.IGNORECASE)),
    ("credential leak", re.compile(r"(?:aws_secret|api[_-]?key|password|bearer\s+[a-z0-9]{20,})", re.IGNORECASE)),
)

# ASI03 Prompt Injection patterns. Heuristic, not exhaustive.
# Aim: catch the patterns every pentester tries in the first 60 seconds.
INJECTION_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("ignore-previous-instructions", re.compile(r"\b(?:ignore|disregard|forget)\s+(?:all\s+|the\s+)?(?:previous|prior|above|earlier|preceding)\s+(?:instructions?|rules?|prompts?|messages?|directives?)\b", re.IGNORECASE)),
    ("role-reset", re.compile(r"\b(?:you\s+are\s+now|from\s+now\s+on\s+you\s+are|act\s+as|pretend\s+(?:to\s+be|you\s+are)|new\s+role|switch\s+roles?)\b", re.IGNORECASE)),
    ("fake system marker", re.compile(r"(?:^|\n)\s*\[?(?:system|assistant|user)\s*\]?\s*[:>]\s", re.IGNORECASE | re.MULTILINE)),
    ("jailbreak prefix (DAN/developer mode)", re.compile(r"\b(?:DAN|do anything now|developer\s+mode|jailbreak|unfiltered|no restrictions?)\b", re.IGNORECASE)),
    ("rule override", re.compile(r"\b(?:override|bypass|skip)\s+(?:safety|guard\w*|filter|policy|rules?|restrictions?)\b", re.IGNORECASE)),
    ("base64 instruction payload", re.compile(r"\b(?:decode\s+(?:this|the following)|base64[:\s]+)\s*[A-Za-z0-9+/]{32,}={0,2}\b", re.IGNORECASE)),
    ("unicode bidi override", re.compile(r"[\u202a-\u202e\u2066-\u2069]")),
    ("inline credential exfil request", re.compile(r"\b(?:reveal|print|output|show|list)\s+(?:your|the)\s+(?:system\s+prompt|instructions?|api[_\s-]?key|secret|token)\b", re.IGNORECASE)),
)

# ASI05 Sensitive Data Exposure patterns.
# Order matters: higher-confidence first, so we surface the most actionable match.
SENSITIVE_DATA_PATTERNS: tuple[tuple[str, str, re.Pattern[str]], ...] = (
    # (label, severity, pattern)
    ("PEM private key", "critical", re.compile(r"-----BEGIN (?:RSA|EC|OPENSSH|PGP|DSA|ENCRYPTED)?\s?PRIVATE KEY-----")),
    ("AWS access key", "critical", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("GitHub PAT (fine-grained)", "critical", re.compile(r"\bgithub_pat_[0-9a-zA-Z_]{70,}\b")),
    ("GitHub token", "critical", re.compile(r"\bgh[pousr]_[0-9A-Za-z]{30,}\b")),
    ("OpenAI API key", "critical", re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_\-]{32,}\b")),
    ("Anthropic API key", "critical", re.compile(r"\bsk-ant-[A-Za-z0-9_\-]{32,}\b")),
    ("Slack token", "critical", re.compile(r"\bxox[abprsu]-[A-Za-z0-9-]{10,}\b")),
    ("JWT", "high", re.compile(r"\beyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\b")),
    ("PyPI token", "critical", re.compile(r"\bpypi-AgE[A-Za-z0-9_\-]{20,}\b")),
    ("SSN (US)", "high", re.compile(r"\b(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b")),
    ("credit card (16 digits)", "high", re.compile(r"\b(?:\d{4}[ -]?){3}\d{4}\b")),
)

# ASI09 Supply Chain / MCP patterns.
MCP_TOOL_PATTERN = re.compile(r"(?:^mcp[_\-\.]|[_\-]mcp[_\-]|^mcp\.)", re.IGNORECASE)

UNIMPLEMENTED_DETECTORS: tuple[tuple[str, str], ...] = (
    ("ASI04", "Memory Poisoning"),
    ("ASI06", "Excessive Agency"),
    ("ASI07", "Unrestricted Resource Consumption"),
    ("ASI08", "Plan Corruption"),
    ("ASI10", "Untraceable Action"),
)


def _tokens(text: str) -> set[str]:
    words = re.findall(r"[a-zA-Z][a-zA-Z0-9_]{1,}", text.lower())
    return {w for w in words if w not in STOPWORDS}


def _extract_user_intent(records: list[AgDRRecord]) -> str:
    """Reconstruct the user's stated goal by concatenating the initial prompts.

    Prefers an explicit ``user_intent`` field when present; otherwise falls back
    to the first few ``llm_start`` prompts.
    """
    explicit = [
        r.payload.user_intent for r in records if r.payload.user_intent
    ]
    if explicit:
        return " ".join(explicit)
    prompts = [
        r.payload.prompt for r in records
        if r.kind == StepKind.LLM_START and r.payload.prompt
    ]
    return " ".join(prompts[:3])


def _tool_context_text(record: AgDRRecord) -> str:
    parts: list[str] = []
    if record.payload.tool_name:
        parts.append(record.payload.tool_name)
    if record.payload.tool_args:
        for value in record.payload.tool_args.values():
            parts.append(str(value))
    return " ".join(parts)


def detect_goal_hijack(records: list[AgDRRecord]) -> list[Finding]:
    """ASI01: user asked for one thing, agent invokes tools unrelated to it."""
    intent_tokens = _tokens(_extract_user_intent(records))
    if not intent_tokens:
        return []

    findings: list[Finding] = []
    for index, record in enumerate(records):
        if record.kind != StepKind.TOOL_START:
            continue
        tool_text = _tool_context_text(record)
        tool_tokens = _tokens(tool_text)
        if not tool_tokens:
            continue

        overlap = len(intent_tokens & tool_tokens) / max(len(intent_tokens | tool_tokens), 1)
        tool_name_lower = (record.payload.tool_name or "").lower()
        looks_sensitive = any(marker in tool_name_lower for marker in SENSITIVE_TOOL_MARKERS)

        if overlap < GOAL_HIJACK_THRESHOLD and looks_sensitive:
            findings.append(
                Finding(
                    asi_id="ASI01",
                    title="Agent Goal Hijack",
                    severity="high",
                    step_id=record.step_id,
                    step_index=index,
                    description=(
                        f"Tool `{record.payload.tool_name}` called with "
                        f"token overlap {overlap:.2f} against the user's stated intent. "
                        f"Threshold {GOAL_HIJACK_THRESHOLD}. Tool is in the sensitive-actions list."
                    ),
                )
            )
    return findings


def detect_tool_misuse(records: list[AgDRRecord]) -> list[Finding]:
    """ASI02: tool invoked with arguments matching known dangerous patterns."""
    findings: list[Finding] = []
    for index, record in enumerate(records):
        if record.kind != StepKind.TOOL_START or not record.payload.tool_args:
            continue
        arg_blob = " ".join(str(v) for v in record.payload.tool_args.values())
        for label, pattern in DANGEROUS_ARG_PATTERNS:
            if pattern.search(arg_blob):
                findings.append(
                    Finding(
                        asi_id="ASI02",
                        title="Tool Misuse",
                        severity="critical",
                        step_id=record.step_id,
                        step_index=index,
                        description=(
                            f"Tool `{record.payload.tool_name}` invoked with arguments "
                            f"matching pattern: {label}."
                        ),
                    )
                )
                break
    return findings


def detect_prompt_injection(records: list[AgDRRecord]) -> list[Finding]:
    """ASI03: llm_start payload carries known prompt-injection shapes.

    Heuristic only. Keyword-based matching against the prompts the agent
    consumed. This surfaces obvious injection attempts (ignore-previous,
    role-reset, fake system markers, jailbreak prefixes, base64 payloads,
    bidi obfuscation, credential-exfil requests). It will miss novel or
    multi-turn social-engineering attacks; for that, use a dedicated
    classifier in the prevention layer.
    """
    findings: list[Finding] = []
    for index, record in enumerate(records):
        if record.kind != StepKind.LLM_START or not record.payload.prompt:
            continue
        prompt = record.payload.prompt
        for label, pattern in INJECTION_PATTERNS:
            match = pattern.search(prompt)
            if match:
                findings.append(
                    Finding(
                        asi_id="ASI03",
                        title="Prompt Injection",
                        severity="high",
                        step_id=record.step_id,
                        step_index=index,
                        description=(
                            f"Prompt at step {index} matches the `{label}` pattern "
                            f"(matched: {match.group(0)[:80]!r})."
                        ),
                    )
                )
                break
    return findings


def _record_text_fields(record: AgDRRecord) -> list[tuple[str, str]]:
    """Return ``(label, text)`` pairs for every user-visible string field on a record."""
    out: list[tuple[str, str]] = []
    p = record.payload
    if p.prompt:
        out.append(("prompt", p.prompt))
    if p.response:
        out.append(("response", p.response))
    if p.tool_output:
        out.append(("tool_output", p.tool_output))
    if p.final_output:
        out.append(("final_output", p.final_output))
    if p.tool_args:
        for k, v in p.tool_args.items():
            out.append((f"tool_args[{k}]", str(v)))
    return out


def detect_sensitive_data_exposure(records: list[AgDRRecord]) -> list[Finding]:
    """ASI05: secrets, credentials, or PII appear in prompts, outputs, or tool args.

    Scans every string field on every record against a curated pattern list
    (PEM keys, provider API keys, GitHub/PyPI tokens, JWT, US SSN, 16-digit
    card numbers). One finding per matching record-field-pattern combination.
    """
    findings: list[Finding] = []
    for index, record in enumerate(records):
        for field_label, text in _record_text_fields(record):
            for pattern_label, severity, pattern in SENSITIVE_DATA_PATTERNS:
                if pattern.search(text):
                    findings.append(
                        Finding(
                            asi_id="ASI05",
                            title="Sensitive Data Exposure",
                            severity=severity,
                            step_id=record.step_id,
                            step_index=index,
                            description=(
                                f"Sensitive pattern `{pattern_label}` detected in "
                                f"{record.kind.value}.{field_label}. Review for unintended "
                                f"credential or PII leakage."
                            ),
                        )
                    )
                    break  # one finding per field, highest-priority match
    return findings


def detect_mcp_supply_chain_risk(records: list[AgDRRecord]) -> list[Finding]:
    """ASI09: tool invocation appears to originate from an MCP server.

    Heuristic: tool_name matching MCP naming conventions (``mcp_*``, ``mcp.*``,
    or ``*_mcp_*``) is surfaced for supply-chain review. The finding does not
    assert the server is malicious; it flags the invocation so auditors can
    cross-reference it against their MCP inventory and verify the server's
    identity, version, and permission scope.
    """
    findings: list[Finding] = []
    for index, record in enumerate(records):
        if record.kind != StepKind.TOOL_START or not record.payload.tool_name:
            continue
        name = record.payload.tool_name
        if MCP_TOOL_PATTERN.search(name):
            findings.append(
                Finding(
                    asi_id="ASI09",
                    title="Supply Chain and MCP Risk",
                    severity="medium",
                    step_id=record.step_id,
                    step_index=index,
                    description=(
                        f"Tool `{name}` matches an MCP server invocation naming "
                        f"pattern. Cross-reference against your MCP inventory and "
                        f"verify server identity, version, and scope."
                    ),
                )
            )
    return findings


def run_detectors(records: list[AgDRRecord]) -> list[Finding]:
    """Run every implemented detector and return a flat list of findings."""
    return [
        *detect_goal_hijack(records),
        *detect_tool_misuse(records),
        *detect_prompt_injection(records),
        *detect_sensitive_data_exposure(records),
        *detect_mcp_supply_chain_risk(records),
    ]
