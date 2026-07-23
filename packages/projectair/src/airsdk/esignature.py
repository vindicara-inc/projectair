"""21 CFR Part 11 electronic-signature manifestation and completeness.

Part 11 §11.50 requires a signed record to carry, in human-readable form, the
printed name of the signer, the date and time of signing, and the meaning of
the signature. AIR records these on a ``HUMAN_APPROVAL`` record; this module
renders the §11.50 manifestation and checks whether a signature is complete.

The signature/record linking required by §11.70 is provided by the chain
itself: a ``HUMAN_APPROVAL`` is bound to the halted action by ``prev_hash``
and cannot be excised or moved without breaking chain verification.
"""
from __future__ import annotations

from datetime import datetime, timezone

from airsdk.types import HumanApproval


def _printed_name(approval: HumanApproval) -> str:
    """Human-readable identifier of the signer (email preferred, else subject)."""
    return approval.approver_email or approval.approver_sub


def _signed_at_iso(approval: HumanApproval) -> str:
    """Signing time as ISO-8601 UTC, from the token's iat claim."""
    return datetime.fromtimestamp(approval.issued_at, tz=timezone.utc).isoformat().replace("+00:00", "Z")


def is_part11_signature(approval: HumanApproval) -> bool:
    """True when the approval carries all §11.50 components: signer, time, meaning."""
    return bool(approval.approver_sub) and approval.issued_at > 0 and approval.meaning is not None


def signature_manifestation(approval: HumanApproval) -> str:
    """Render the §11.50 signature manifestation as a single human-readable line.

    Includes the printed name, the signing date/time (UTC), and the meaning of
    the signature. When the meaning is absent the manifestation says so plainly
    rather than implying a complete signature.
    """
    meaning = approval.meaning.value if approval.meaning is not None else "(meaning not recorded)"
    return (
        f"Signed by {_printed_name(approval)} "
        f"on {_signed_at_iso(approval)} "
        f"as: {meaning} "
        f"(issuer {approval.issuer})"
    )
