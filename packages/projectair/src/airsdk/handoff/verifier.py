"""The eight-step cross-agent verifier (Section 8.2 of the Layer 4 spec).

Inputs: a set of chain files (JSON Lines) that share a Parent Trace ID.
Output: pass / fail with precise diagnostics pointing at the record that
broke verification, plus ``jwt_reverified`` recording whether the
capability-token JWT was cryptographically re-verified (it can only be when
the handoff record carries ``raw_jwt``). Wave 1 runs the eight steps for
single-tenant chains using LOCAL_DEV identities; construct the verifier with
``require_capability_token_jwt=True`` to fail closed when the issuer-signed
JWT is absent. Cross-tenant Fulcio chain validation runs in lenient mode
(logged, not enforced) until v1.5.

The temporal-ordering math in :func:`verify_temporal_ordering` is the
canonical reference implementation per Section 15.15. Naive comparison
(``acceptance.ts_iso > handoff.ts_iso``) is explicitly forbidden.
"""
from __future__ import annotations

import datetime as _dt
import json
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .exceptions import (
    CrossAgentVerificationError,
    HandoffPairingError,
    HandoffRecordInvalidError,
    PTIDInvalidError,
    ReplayAnomalyError,
    TemporalOrderingError,
)
from .fulcio import FulcioTrustBundle, verify_fulcio_leaf
from .handoff_record import (
    SCHEMA_HANDOFF,
    SCHEMA_HANDOFF_ACCEPTANCE,
    verify_record_content_hash,
    verify_record_signature,
)
from .identity import IdentityFormat, cert_hash_from_der
from .idp.base import AdapterRouter, IdPAdapter
from .trace import validate_ptid
from .validation_proof import RekorBackend, verify_validation_proof

DEFAULT_SKEW_TOLERANCE_SECONDS = 5


def _parse_iso8601(ts: str) -> float:
    """Return the Unix timestamp (float seconds) for an ISO 8601 string."""
    if ts.endswith("Z"):
        ts = ts[:-1] + "+00:00"
    return _dt.datetime.fromisoformat(ts).timestamp()


def verify_temporal_ordering(
    *,
    acceptance_ts_iso: str,
    handoff_ts_iso: str,
    acceptance_timeout_seconds: int,
    skew_tolerance_seconds: int = DEFAULT_SKEW_TOLERANCE_SECONDS,
) -> None:
    """Two-bound temporal ordering check per Section 15.15.

    Both bounds must hold:
      lower: acceptance_ts + skew >= handoff_ts (receiver lagging sender)
      upper: acceptance_ts <= handoff_ts + timeout + skew (acceptance window)
    """
    a = _parse_iso8601(acceptance_ts_iso)
    h = _parse_iso8601(handoff_ts_iso)
    if a + skew_tolerance_seconds < h:
        raise TemporalOrderingError(
            failed_bound="lower",
            actual_delta_seconds=h - a,
            configured_tolerance_seconds=float(skew_tolerance_seconds),
        )
    upper_limit = h + acceptance_timeout_seconds + skew_tolerance_seconds
    if a > upper_limit:
        raise TemporalOrderingError(
            failed_bound="upper",
            actual_delta_seconds=a - h,
            configured_tolerance_seconds=float(
                acceptance_timeout_seconds + skew_tolerance_seconds
            ),
        )


def _load_jsonl(path: Path) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as fh:
        for n, line in enumerate(fh, 1):
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError as e:
                raise CrossAgentVerificationError(
                    f"{path}:{n} not valid JSON: {e}"
                ) from e
            if isinstance(obj, dict):
                records.append(obj)
    return records


@dataclass(slots=True)
class Chain:
    """One agent's chain — a list of mixed legacy and Layer 4 records."""

    path: Path
    records: list[dict[str, Any]]
    handoff_records: list[dict[str, Any]] = field(default_factory=list)
    acceptance_records: list[dict[str, Any]] = field(default_factory=list)
    agent_id: str | None = None

    @classmethod
    def from_path(cls, path: Path | str) -> Chain:
        p = Path(path)
        records = _load_jsonl(p)
        chain = cls(path=p, records=records)
        for r in records:
            schema = r.get("schema")
            if schema == SCHEMA_HANDOFF:
                chain.handoff_records.append(r)
                chain.agent_id = r.get("agent", {}).get("id")
            elif schema == SCHEMA_HANDOFF_ACCEPTANCE:
                chain.acceptance_records.append(r)
                chain.agent_id = r.get("agent", {}).get("id")
        return chain


@dataclass(slots=True)
class ChainSet:
    chains: list[Chain]

    @classmethod
    def from_paths(cls, paths: Iterable[Path | str]) -> ChainSet:
        return cls(chains=[Chain.from_path(p) for p in paths])

    def all_layer4_records(self) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        for c in self.chains:
            out.extend(c.handoff_records)
            out.extend(c.acceptance_records)
        return out


@dataclass(slots=True)
class VerificationResult:
    parent_trace_id: str
    chains_examined: int
    handoffs: int
    acceptances: int
    diagnostics: list[str] = field(default_factory=list)
    flags: list[str] = field(default_factory=list)
    passed: bool = True
    # True only when at least one capability-token JWT was cryptographically
    # re-verified against its issuer (raw_jwt present and checked). When False,
    # pairing rested on jti match + the agent-signed validation proof, which a
    # compromised target agent could in principle author. Callers MUST surface
    # this: a green ``passed`` with ``jwt_reverified is False`` is a partial,
    # not a full, cross-agent verification.
    jwt_reverified: bool = False

    def fail(self, message: str) -> None:
        self.passed = False
        self.diagnostics.append(message)

    def flag(self, message: str) -> None:
        self.flags.append(message)


def _public_key_from_local_dev_chain_hash(
    record: dict[str, Any], identity_pubkeys: dict[str, Ed25519PublicKey]
) -> Ed25519PublicKey:
    """Return the Ed25519 public key for the record's signing agent.

    Wave 1 uses LOCAL_DEV identities supplied via ``identity_pubkeys``.
    Sigstore Fulcio resolution ships in v1.5.
    """
    cert_hash = record.get("agent", {}).get("identity_certificate_hash")
    if not isinstance(cert_hash, str):
        raise HandoffRecordInvalidError("agent.identity_certificate_hash missing")
    pk = identity_pubkeys.get(cert_hash)
    if pk is None:
        raise CrossAgentVerificationError(
            f"no identity public key registered for cert_hash={cert_hash!r}; "
            f"supply via CrossAgentVerifier.register_identity()"
        )
    return pk


@dataclass(slots=True)
class CrossAgentVerifier:
    """Implements Section 8.2 over a :class:`ChainSet`."""

    adapter_router: AdapterRouter
    rekor_backend: RekorBackend | None = None
    skew_tolerance_seconds: int = DEFAULT_SKEW_TOLERANCE_SECONDS
    identity_pubkeys: dict[str, Ed25519PublicKey] = field(default_factory=dict)
    fulcio_trust_bundle: FulcioTrustBundle | None = None
    fulcio_certs: dict[str, bytes] = field(default_factory=dict)
    # Fail-closed posture for the capability-token step. When True, a handoff
    # whose record does not carry the issuer-signed JWT (``raw_jwt``) cannot be
    # cryptographically re-verified, so the chain set FAILS rather than passing
    # on the jti-match + validation-proof path alone. Default False preserves
    # the sidecar-JWT deployment model (the raw JWT is stored out of band); the
    # ``air handoff verify`` CLI sets it True by default. Regardless of this
    # flag, ``VerificationResult.jwt_reverified`` records whether the JWT was
    # actually checked.
    require_capability_token_jwt: bool = False

    def register_identity(self, cert_hash: str, public_key: Ed25519PublicKey) -> None:
        """Wave 1 LOCAL_DEV mapping from cert_hash to Ed25519 public key."""
        self.identity_pubkeys[cert_hash] = public_key

    def register_fulcio_cert(self, cert_der: bytes) -> str:
        """Register a Fulcio leaf cert (Wave 2), keyed by its identity_certificate_hash.

        Returns that hash. The cert is validated lazily, at verification time,
        against the trust bundle as-of each record's own timestamp.
        """
        cert_hash = cert_hash_from_der(cert_der)
        self.fulcio_certs[cert_hash] = cert_der
        return cert_hash

    def _record_time(self, record: dict[str, Any]) -> _dt.datetime | None:
        ts = record.get("ts_iso")
        if not isinstance(ts, str):
            return None
        return _dt.datetime.fromtimestamp(_parse_iso8601(ts), tz=_dt.timezone.utc)

    def _resolve_identity_key(self, record: dict[str, Any]) -> Ed25519PublicKey:
        """Resolve the Ed25519 signing key for ``record``'s agent identity.

        With a Fulcio trust bundle configured (Wave 2 cross-tenant), every
        identity MUST be Sigstore Fulcio: the registered leaf cert is validated
        against the bundle as-of the record's timestamp and its key returned;
        LOCAL_DEV and X.509 identities are rejected (fail-closed). Without a
        bundle (Wave 1 single-tenant), LOCAL_DEV keys are resolved from the
        registered pubkey map exactly as before.
        """
        fmt = record.get("agent", {}).get("identity_certificate_format")
        if self.fulcio_trust_bundle is not None:
            if fmt != IdentityFormat.SIGSTORE_FULCIO.value:
                raise CrossAgentVerificationError(
                    f"identity format {fmt!r} rejected: a Fulcio trust bundle is "
                    "configured, so every agent identity must be Sigstore Fulcio",
                )
            cert_hash = record.get("agent", {}).get("identity_certificate_hash")
            if not isinstance(cert_hash, str):
                raise HandoffRecordInvalidError("agent.identity_certificate_hash missing")
            cert_der = self.fulcio_certs.get(cert_hash)
            if cert_der is None:
                raise CrossAgentVerificationError(
                    f"no Fulcio certificate registered for cert_hash={cert_hash!r}; "
                    "supply via CrossAgentVerifier.register_fulcio_cert()",
                )
            if cert_hash_from_der(cert_der) != cert_hash:
                raise CrossAgentVerificationError(
                    f"registered Fulcio cert does not match record cert_hash={cert_hash!r}",
                )
            return verify_fulcio_leaf(
                cert_der, self.fulcio_trust_bundle, at_time=self._record_time(record)
            )
        if fmt == IdentityFormat.SIGSTORE_FULCIO.value:
            raise CrossAgentVerificationError(
                "SIGSTORE_FULCIO identity requires a Fulcio trust bundle; construct "
                "CrossAgentVerifier(fulcio_trust_bundle=...)",
            )
        return _public_key_from_local_dev_chain_hash(record, self.identity_pubkeys)

    def _route_capability_issuer(
        self, token_iss: object, source_record: dict[str, Any]
    ) -> IdPAdapter:
        """Route a capability-token issuer to an adapter.

        Single-tenant (no bundle): strict :meth:`AdapterRouter.route`. Cross-
        tenant (bundle set): :meth:`route_fulcio_vouched`, where the source
        agent's Fulcio cert must vouch for the token issuer; unregistered,
        unvouched issuers still fail closed.
        """
        if not isinstance(token_iss, str):
            raise CrossAgentVerificationError("capability token missing a string issuer")
        if self.fulcio_trust_bundle is None:
            return self.adapter_router.route(token_iss)
        cert_hash = source_record.get("agent", {}).get("identity_certificate_hash")
        cert_der = self.fulcio_certs.get(cert_hash) if isinstance(cert_hash, str) else None
        if cert_der is None:
            return self.adapter_router.route(token_iss)
        return self.adapter_router.route_fulcio_vouched(
            token_iss,
            leaf_cert_der=cert_der,
            trust_bundle=self.fulcio_trust_bundle,
            at_time=self._record_time(source_record),
        )

    def verify_chain_set(
        self, chain_set: ChainSet, parent_trace_id: str
    ) -> VerificationResult:
        validate_ptid(parent_trace_id)

        result = VerificationResult(
            parent_trace_id=parent_trace_id,
            chains_examined=len(chain_set.chains),
            handoffs=sum(len(c.handoff_records) for c in chain_set.chains),
            acceptances=sum(len(c.acceptance_records) for c in chain_set.chains),
        )

        layer4_records = chain_set.all_layer4_records()
        if not layer4_records:
            result.fail("no Layer 4 handoff or acceptance records found in chain set")
            return result

        # Step 1: PTID consistency
        for r in layer4_records:
            ptid = r.get("trace", {}).get("parent_trace_id")
            if ptid != parent_trace_id:
                result.fail(
                    f"PTID mismatch in {r.get('schema')} step_n={r.get('step_n')}: "
                    f"got {ptid!r}, expected {parent_trace_id!r}"
                )
                return result
            try:
                validate_ptid(ptid)
            except PTIDInvalidError as e:
                result.fail(f"PTID format invalid: {e}")
                return result

        # Step 2: identify root (depth=0)
        depth_zero = [r for r in layer4_records if r.get("trace", {}).get("depth") == 0]
        if not depth_zero:
            result.fail("no depth=0 record found; cannot identify root")
            return result

        # Step 3+4: build handoff graph and pair with acceptances
        handoffs = [r for r in layer4_records if r.get("schema") == SCHEMA_HANDOFF]
        acceptances = [
            r for r in layer4_records if r.get("schema") == SCHEMA_HANDOFF_ACCEPTANCE
        ]

        # idempotency: no two acceptances may share source_handoff_record_hash
        seen_sources: dict[str, dict[str, Any]] = {}
        for a in acceptances:
            src_hash = a.get("acceptance", {}).get("source_handoff_record_hash")
            if src_hash in seen_sources:
                raise ReplayAnomalyError(
                    f"two handoff_acceptance records reference the same "
                    f"source_handoff_record_hash={src_hash!r}; chain set rejected"
                )
            seen_sources[src_hash] = a

        # pair each handoff to exactly one acceptance
        for h in handoffs:
            src_hash = h.get("content_hash")
            if not isinstance(src_hash, str):
                raise HandoffPairingError(
                    "handoff record missing content_hash"
                )
            paired = seen_sources.get(src_hash)
            if paired is None:
                raise HandoffPairingError(
                    f"handoff with content_hash={src_hash!r} has no matching "
                    f"acceptance in the chain set"
                )
            self._verify_pair(h, paired, result)

        # Step 6: intra-chain integrity for every L4 record
        for r in layer4_records:
            try:
                verify_record_content_hash(r)
                pk = self._resolve_identity_key(r)
                verify_record_signature(r, pk)
            except HandoffRecordInvalidError as e:
                result.fail(
                    f"intra-chain integrity failed at {r.get('schema')} "
                    f"step_n={r.get('step_n')}: {e}"
                )
                return result

        # Step 8: identity cert chain validation (lenient for LOCAL_DEV)
        for r in layer4_records:
            fmt = r.get("agent", {}).get("identity_certificate_format")
            if fmt == IdentityFormat.LOCAL_DEV.value:
                result.flag(
                    "LOCAL_DEV identity in use: chain is not anchored to a real CA root; "
                    "production deployments MUST use Sigstore Fulcio or X.509 PEM"
                )
                break

        return result

    def _verify_pair(
        self,
        handoff: dict[str, Any],
        acceptance: dict[str, Any],
        result: VerificationResult,
    ) -> None:
        h_body = handoff.get("handoff", {})
        a_body = acceptance.get("acceptance", {})
        target_id = h_body.get("target_agent_id")
        target_in_acceptance = acceptance.get("agent", {}).get("id")
        source_id = handoff.get("agent", {}).get("id")
        source_in_acceptance = a_body.get("source_agent_id")

        # Step 4 pairing rules
        if target_id != target_in_acceptance:
            raise HandoffPairingError(
                f"target_agent_id mismatch: handoff says {target_id!r}, "
                f"acceptance is from {target_in_acceptance!r}"
            )
        if source_id != source_in_acceptance:
            raise HandoffPairingError(
                f"source_agent_id mismatch: handoff is from {source_id!r}, "
                f"acceptance says {source_in_acceptance!r}"
            )
        if h_body.get("capability_token", {}).get("jti") != a_body.get(
            "capability_token_received_jti"
        ):
            raise HandoffPairingError("capability token jti mismatch")
        if h_body.get("delegation_intent_hash") != a_body.get(
            "delegation_intent_hash_acknowledged"
        ):
            raise HandoffPairingError("delegation_intent_hash mismatch")

        # Step 5: capability token verification via AdapterRouter
        cap = h_body.get("capability_token", {})
        token_iss = cap.get("issuer")
        adapter = self._route_capability_issuer(token_iss, handoff)
        raw_jwt = cap.get("raw_jwt")
        ptid = handoff.get("trace", {}).get("parent_trace_id")
        if isinstance(raw_jwt, str) and raw_jwt:
            adapter.verify_capability_token(
                raw_jwt=raw_jwt,
                expected_audience=target_id,
                expected_parent_trace_id=ptid,
            )
            result.jwt_reverified = True
        elif self.require_capability_token_jwt:
            # Fail-closed: without the issuer-signed JWT we cannot
            # cryptographically verify the capability token, and the validation
            # proof alone is authored by the (possibly compromised) target
            # agent. A strict verifier refuses to pass.
            result.fail(
                "capability-token JWT re-verification required but no raw_jwt is "
                "present in the handoff record; pairing on jti + agent-signed "
                "validation proof alone is not accepted in strict mode "
                f"(adapter routed={adapter.__class__.__name__})"
            )
            return
        else:
            # Permissive (sidecar-JWT) mode: pairing relies on jti string match
            # plus the agent-signed, Rekor-anchored, coordinate-bound validation
            # proof. That binds the acceptance to a specific jti and anchored
            # time, but does NOT cryptographically verify the JWT signature
            # here. ``jwt_reverified`` stays False so callers can surface that
            # this was a partial verification.
            result.flag(
                "step 5 capability-token JWT re-verification deferred "
                "(no raw_jwt in handoff record); pairing relies on jti "
                "string match + agent-signed validation proof; "
                f"adapter routed={adapter.__class__.__name__}"
            )

        # Step 5b: validation proof. The validating (target) agent's key is
        # resolved the same way as every other identity: Fulcio-validated when a
        # trust bundle is configured, else the Wave 1 registered pubkey.
        proof = a_body.get("capability_token_validation_proof", {})
        pk = self._resolve_identity_key(acceptance)
        verify_validation_proof(
            proof=proof,
            validating_agent_public_key=pk,
            rekor_backend=self.rekor_backend,
        )

        # Step 7: temporal ordering (two-bound math)
        timeout = h_body.get("fail_policy", {}).get("acceptance_timeout_seconds", 30)
        verify_temporal_ordering(
            acceptance_ts_iso=acceptance["ts_iso"],
            handoff_ts_iso=handoff["ts_iso"],
            acceptance_timeout_seconds=int(timeout),
            skew_tolerance_seconds=self.skew_tolerance_seconds,
        )


__all__ = [
    "DEFAULT_SKEW_TOLERANCE_SECONDS",
    "Chain",
    "ChainSet",
    "CrossAgentVerifier",
    "VerificationResult",
    "verify_temporal_ordering",
]
