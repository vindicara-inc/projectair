"""Start an agent session bound to a human delegation.

Emit the DELEGATION genesis record, then an INTENT_DECLARATION carrying the
authorized scope so Structural Verification enforces exactly what the human
authorized. Call immediately after constructing the recorder and before any
agent step, so the delegation is the chain root.

Prefer ``AIRRecorder(..., delegation=grant)`` or ``recorder.open_delegation(grant)``;
this standalone helper is the no-edit option and forwards to the recorder method.
"""
from __future__ import annotations

from airsdk.recorder import AIRRecorder
from airsdk.types import AgDRRecord, DelegationGrant


def open_delegation(recorder: AIRRecorder, grant: DelegationGrant) -> AgDRRecord:
    """Write the session-genesis DELEGATION record and declare its scope.

    Must be the first thing emitted on the chain. Construct the recorder
    WITHOUT ``intent_spec=`` (so it does not auto-emit an INTENT_DECLARATION
    ahead of the delegation), then call this.

    Returns the DELEGATION record.
    """
    return recorder.open_delegation(grant)
