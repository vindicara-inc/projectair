"""Event kinds + per-kind redaction policy for the Vindicara ops chain.

Every event the ops chain emits is one of the kinds enumerated in :class:`OpsKind`.
For each kind, ``REDACTION_POLICY`` declares which payload fields are safe to
publish in clear text on the public chain and which must be replaced by a
BLAKE3 hash of the original value before publication.

Default deny: any payload field NOT listed in ``public`` is redacted on
publication. The :mod:`airsdk` chain on disk (and in DynamoDB) keeps the full
unredacted payload so internal verification still works; only the public S3
JSONL goes through redaction.
"""
from __future__ import annotations

from enum import StrEnum
from typing import Final


class OpsKind(StrEnum):
    """Vindicara-specific event kinds. Each maps to a tool_name in the AgDR chain."""

    API_REQUEST = "vindicara.api.request"
    DASHBOARD_LOGIN = "vindicara.dashboard.auth.login"
    DASHBOARD_SIGNUP = "vindicara.dashboard.auth.signup"
    DASHBOARD_MFA_ENROLL = "vindicara.dashboard.auth.mfa_enroll"
    DASHBOARD_MFA_VERIFY = "vindicara.dashboard.auth.mfa_verify"
    DASHBOARD_PASSWORD_RESET = "vindicara.dashboard.auth.password_reset"  # noqa: S105
    DASHBOARD_API_KEY_ISSUE = "vindicara.dashboard.api_key.issue"
    DASHBOARD_API_KEY_REVOKE = "vindicara.dashboard.api_key.revoke"
    OPS_CLI_KEY_REVOKE = "vindicara.ops.key_revoke"
    OPS_CLI_DSAR_FULFILL = "vindicara.ops.dsar_fulfill"
    OPS_CLI_REDACTION_CHANGE = "vindicara.ops.redaction_change"


# Per-kind redaction policy. Fields in ``public`` are emitted unredacted in the
# published JSONL; everything else is replaced by ``"blake3:" || hex_digest``.
# A missing kind defaults to the ``_DEFAULT`` entry (which publishes nothing
# beyond kind, timestamp, ord, and chain_id). Aim conservative.
REDACTION_POLICY: Final[dict[str, frozenset[str]]] = {
    OpsKind.API_REQUEST.value: frozenset({"method", "path_template", "status_code", "duration_ms"}),
    OpsKind.DASHBOARD_LOGIN.value: frozenset({"outcome", "duration_ms"}),
    OpsKind.DASHBOARD_SIGNUP.value: frozenset({"outcome", "duration_ms"}),
    OpsKind.DASHBOARD_MFA_ENROLL.value: frozenset({"outcome", "duration_ms"}),
    OpsKind.DASHBOARD_MFA_VERIFY.value: frozenset({"outcome", "duration_ms"}),
    OpsKind.DASHBOARD_PASSWORD_RESET.value: frozenset({"outcome", "duration_ms"}),
    OpsKind.DASHBOARD_API_KEY_ISSUE.value: frozenset({"outcome", "duration_ms"}),
    OpsKind.DASHBOARD_API_KEY_REVOKE.value: frozenset({"outcome", "duration_ms"}),
    OpsKind.OPS_CLI_KEY_REVOKE.value: frozenset({"outcome", "approver_sub", "duration_ms"}),
    OpsKind.OPS_CLI_DSAR_FULFILL.value: frozenset({"outcome", "approver_sub", "duration_ms"}),
    OpsKind.OPS_CLI_REDACTION_CHANGE.value: frozenset({"outcome", "approver_sub", "duration_ms"}),
}

# Field-name denylist for the hypothesis property test. Any field whose name
# matches one of these substrings (case-insensitive) MUST never appear in the
# published JSONL except as a BLAKE3 hash. Test-only; runtime redaction goes
# by the per-kind whitelist above.
DENYLIST_FIELD_NAMES: Final[frozenset[str]] = frozenset({
    "token",
    "secret",
    "password",
    "passphrase",
    "session",
    "cookie",
    "authorization",
    "bearer",
    "key",
    "email",
    "ip",
    "ip_address",
    "user_agent",
    "phone",
    "ssn",
    "credit_card",
    "card_number",
})

PUBLIC_FIELDS_DEFAULT: Final[frozenset[str]] = frozenset()
