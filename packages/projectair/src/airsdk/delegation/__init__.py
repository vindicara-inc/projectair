"""Delegated Authority: bind an agent session to the human who authorized it.

No agent is autonomous. Every agent runs on authority a human delegated. This
package records that delegation as the genesis of the AgDR chain, so every
action in the session is provably traceable to a named, authenticated person
under a named policy and scope.

Public surface:
    open_delegation(recorder, grant)        -> emit the genesis DELEGATION record
    mint_grant_from_auth0(...)              -> phase 1, reuse the shipped Auth0Verifier
    verify_webauthn_assertion(...)          -> phase 2, native WebAuthn (optional dep)
    mint_grant_from_webauthn(...)           -> phase 2, build a grant from an assertion

The WebAuthn helpers live in ``airsdk.delegation.webauthn`` and require the
optional ``webauthn`` dependency (``pip install 'projectair[webauthn]'``). They
are intentionally not imported here so the package imports cleanly without it.
"""
from __future__ import annotations

from airsdk.delegation.auth0_passkey import mint_grant_from_auth0
from airsdk.delegation.session import open_delegation

__all__ = ["mint_grant_from_auth0", "open_delegation"]
