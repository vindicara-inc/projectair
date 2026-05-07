"""Anchoring exception hierarchy.

Hard failures (signature invalid, proof invalid, nonce mismatch) are always
raised. Soft failures (TSA timeout, Rekor 5xx) are caught by the
orchestrator's failure policy and either degrade silently (fail-open) or
halt the agent action (fail-closed) per operator configuration.
"""
from __future__ import annotations


class AnchoringError(Exception):
    """Base class for all anchoring errors."""


class TSAError(AnchoringError):
    """Base class for RFC 3161 TSA errors."""


class TSAUnreachableError(TSAError):
    """The TSA could not be reached within the configured timeout."""


class TSARateLimitedError(TSAError):
    """The TSA returned 429 Too Many Requests.

    Public TSAs (FreeTSA in particular) throttle aggressive callers. The
    default 10-second cadence translates to ~360 requests/hour per agent
    process; a fleet of 10 instances on the same TSA can trip the limiter.
    Operators running at that scale should pin a paid TSA via ``tsa_url``.
    """


class TSAResponseInvalidError(TSAError):
    """The TSA returned a malformed or non-success response body."""


class TSASignatureInvalidError(TSAError):
    """The TSA-issued token failed signature verification.

    This is a hard failure: never accept a token whose signature does not
    verify. A valid token's signature is the only thing that anchors trust.
    """


class TSANonceMismatchError(TSAError):
    """The TSA returned a token whose nonce does not match the request.

    Possible replay attack: an attacker is feeding an old TSA response back
    to us in place of a fresh one. Refuse the token.
    """


class TSACertificateInvalidError(TSAError):
    """The TSA's certificate chain failed validation against bundled roots."""


class RekorError(AnchoringError):
    """Base class for Sigstore Rekor errors."""


class RekorUnreachableError(RekorError):
    """Rekor could not be reached within the configured timeout."""


class RekorRateLimitedError(RekorError):
    """Rekor returned 429 after the configured retry budget was exhausted."""


class RekorProofInvalidError(RekorError):
    """A Rekor inclusion proof failed verification.

    Hard failure. A bad proof means the entry is not actually in the log
    at the claimed position; trust is broken until the entry is re-fetched.
    """


class RekorEntryRejectedError(RekorError):
    """Rekor refused the entry (4xx other than 429)."""


class AnchorRequiredError(AnchoringError):
    """Raised in fail-closed mode when an anchor cannot be obtained.

    The orchestrator surfaces this when an action is configured for
    fail-closed and the anchor pipeline is unhealthy (TSA or Rekor
    unreachable, or the unanchored backlog has exceeded its bound). The
    agent's containment policy decides what to do next.
    """
