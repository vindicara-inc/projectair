"""Containment exception hierarchy.

Layer 3 v1. These are raised by the ``ContainmentPolicy`` when a rule
trips and surface through ``AIRRecorder.tool_start``. The agent code
catches the exception, halts the action, and either reports the block
(``BlockedActionError``) or initiates a human-approval flow
(``StepUpRequiredError``).

Both subclasses include a structured ``decision`` payload so downstream
log/alerting code can distinguish "blocked" from "needs human" without
parsing exception messages.
"""
from __future__ import annotations


class ContainmentError(Exception):
    """Base class for all containment failures."""


class BlockedActionError(ContainmentError):
    """The action is denied. The agent must not execute it.

    Raised when a deny-tool, deny-arg, or block-on-findings rule trips.
    The TOOL_START record is written to the chain with ``blocked=True``
    and ``blocked_reason`` populated, so the audit trail captures the
    attempt.
    """

    def __init__(self, reason: str, *, tool_name: str | None = None) -> None:
        super().__init__(reason)
        self.reason = reason
        self.tool_name = tool_name


class StepUpRequiredError(ContainmentError):
    """The action is paused pending authenticated human approval.

    Raised when a ``step_up_required`` rule trips. The agent should
    present the ``challenge_id`` to the responsible human (via Auth0
    Universal Login URL, push notification, or an out-of-band channel),
    obtain a verified Auth0 token, and call
    ``recorder.approve(challenge_id, token)`` to resume.

    The TOOL_START record is written with ``blocked=True`` and the
    ``challenge_id`` populated, so the chain captures both the attempt
    and the pending approval state. If approval never arrives the chain
    reflects a halted action; if approval arrives, a HUMAN_APPROVAL
    record follows.
    """

    def __init__(
        self,
        reason: str,
        *,
        challenge_id: str,
        tool_name: str | None = None,
    ) -> None:
        super().__init__(reason)
        self.reason = reason
        self.challenge_id = challenge_id
        self.tool_name = tool_name


class ApprovalInvalidError(ContainmentError):
    """An approval token was rejected by the verifier.

    Reasons: signature failed, issuer mismatch, audience mismatch,
    expired, replay, or claims do not authorize the requested challenge.
    Treat as a hard failure - the action remains halted.
    """


class ChallengeNotFoundError(ContainmentError):
    """The challenge_id presented for approval is not pending.

    Either the challenge was never issued, was already approved/denied,
    or has expired. The recorder rejects the approval call.
    """
