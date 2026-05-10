"""Framework-agnostic recorder for writing signed AgDR records.

``AIRRecorder`` is the primitive. It wraps a ``Signer`` and one or more
:class:`Transport` sinks, and exposes one method per AgDR step kind.
Framework integrations (LangChain, OpenAI SDK, Anthropic SDK, and any
custom code) all build on top of it.

By default a recorder writes to a single :class:`FileTransport` so the
historical ``log_path``-only constructor still works unchanged. Callers
that want to also push records to AIR Cloud or any custom sink pass an
explicit ``transports=`` list.
"""
from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.mldsa import MLDSA65PrivateKey
from cryptography.hazmat.primitives.serialization import load_pem_private_key

from airsdk.agdr import SigningKey, Signer, _uuid7
from airsdk.containment import (
    Auth0Verifier,
    BlockedActionError,
    ChallengeNotFoundError,
    ContainmentPolicy,
    Decision,
    StepUpRequiredError,
)
from airsdk.transport import FileTransport, Transport
from airsdk.types import AgDRPayload, AgDRRecord, HumanApproval, SigningAlgorithm, StepKind

if TYPE_CHECKING:
    from airsdk.anchoring import AnchoringOrchestrator
    from airsdk.types import Finding


def resolve_signing_key(
    key: str | SigningKey | None,
    algorithm: SigningAlgorithm = SigningAlgorithm.ED25519,
) -> SigningKey | None:
    """Accept a private key as hex seed, PEM, or raw key instance.

    PEM keys are auto-detected (Ed25519 or ML-DSA-65). Hex seeds use
    ``algorithm`` to pick the right key type. Returns ``None`` when
    ``key`` is ``None`` so callers can fall back to ``Signer.generate()``.
    """
    if key is None:
        return None
    if isinstance(key, (Ed25519PrivateKey, MLDSA65PrivateKey)):
        return key
    data = key.strip()
    if data.startswith("-----BEGIN"):
        priv = load_pem_private_key(data.encode(), password=None)
        if isinstance(priv, (Ed25519PrivateKey, MLDSA65PrivateKey)):
            return priv
        raise ValueError(f"key PEM must hold Ed25519 or ML-DSA-65, got {type(priv).__name__}")
    try:
        seed = bytes.fromhex(data)
    except ValueError as exc:
        raise ValueError("key must be a PEM-encoded private key or a 64-char hex seed") from exc
    if len(seed) != 32:
        raise ValueError(f"hex key must decode to 32 bytes, got {len(seed)}")
    if algorithm == SigningAlgorithm.ML_DSA_65:
        return MLDSA65PrivateKey.from_seed_bytes(seed)
    return Ed25519PrivateKey.from_private_bytes(seed)


class AIRRecorder:
    """Write signed AgDR records to one or more transports. Framework-agnostic.

    Parameters
    ----------
    log_path:
        Where AgDR records are appended on disk. Required for backward
        compatibility; passed to the default ``FileTransport`` when
        ``transports`` is not provided. Parent directories are created on
        first write.
    key:
        Ed25519 signing key. Accepts a 64-char hex seed, a PEM-encoded
        private key, or a raw ``Ed25519PrivateKey``. When ``None``, a fresh
        keypair is generated for the session.
    user_intent:
        Optional plain-text statement of what the user asked the agent to
        do. Attached to every record this recorder emits, so the ASI01
        Goal Hijack detector has a reliable anchor even if the underlying
        chain never echoes the original prompt.
    transports:
        Optional list of :class:`Transport` sinks. When omitted the
        recorder uses a single ``FileTransport(log_path)``, matching
        historical behaviour. Pass an explicit list to compose multiple
        sinks (e.g. ``[FileTransport(log_path), HTTPTransport(endpoint)]``)
        for AIR Cloud ingestion alongside local disk.
    """

    def __init__(
        self,
        log_path: str | Path,
        key: str | SigningKey | None = None,
        *,
        user_intent: str | None = None,
        transports: list[Transport] | None = None,
        containment: ContainmentPolicy | None = None,
        auth0_verifier: Auth0Verifier | None = None,
        signing_algorithm: SigningAlgorithm = SigningAlgorithm.ED25519,
    ) -> None:
        priv = resolve_signing_key(key, algorithm=signing_algorithm)
        self._signer = Signer(priv) if priv is not None else Signer.generate(signing_algorithm)
        self._log_path = Path(log_path).expanduser()
        self._log_path.parent.mkdir(parents=True, exist_ok=True)
        self._user_intent = user_intent
        self._transports: list[Transport] = transports if transports is not None else [FileTransport(self._log_path)]
        self._orchestrator: AnchoringOrchestrator | None = None
        self._containment = containment
        self._auth0 = auth0_verifier
        # Pending step-up challenges keyed by challenge_id. Each value is the
        # original tool action so ``approve`` can resume it after a verified
        # token arrives.
        self._pending: dict[str, dict[str, Any]] = {}
        # Findings the policy uses for ``block_on_findings`` rules. Operators
        # update this list as detectors fire (or pass run_detectors output
        # directly into ``tool_start``).
        self._prior_findings: list[Finding] = []

    @property
    def public_key_hex(self) -> str:
        """Ed25519 public key of the signer. Verifiers use this."""
        return self._signer.public_key_hex

    @property
    def log_path(self) -> Path:
        """Where this recorder appends its JSONL (default ``FileTransport`` only)."""
        return self._log_path

    @property
    def transports(self) -> list[Transport]:
        """Live list of transports this recorder is fanning records out to."""
        return self._transports

    def add_transport(self, transport: Transport) -> None:
        """Register an additional transport sink at runtime.

        Useful when the cloud endpoint or API key is only known after the
        recorder has been constructed (e.g. lazy login flow).
        """
        self._transports.append(transport)

    # -- Step emitters -----------------------------------------------------

    def llm_start(self, *, prompt: str, **extra: Any) -> AgDRRecord:
        """Agent is about to call an LLM with ``prompt``."""
        return self._emit(StepKind.LLM_START, {"prompt": prompt, **extra})

    def llm_end(self, *, response: str, **extra: Any) -> AgDRRecord:
        """LLM returned ``response``."""
        return self._emit(StepKind.LLM_END, {"response": response, **extra})

    def tool_start(
        self,
        *,
        tool_name: str,
        tool_args: dict[str, Any] | None = None,
        prior_findings: list[Finding] | None = None,
        **extra: Any,
    ) -> AgDRRecord:
        """Agent is about to invoke a tool.

        When a containment policy is attached, this is the gate where
        deny / step-up rules are enforced. The policy is consulted
        before any side effect happens. Three outcomes:

        - allowed: write a normal TOOL_START and return it
        - blocked: write a TOOL_START with ``blocked=True`` plus the
          reason, then raise ``BlockedActionError`` so the agent does
          not call the tool
        - step-up: write a TOOL_START with ``blocked=True`` and a
          ``challenge_id``, then raise ``StepUpRequiredError`` so the
          agent can route the human through Auth0 and call
          ``approve(challenge_id, token)`` to resume

        ``prior_findings`` is the detector findings list for
        ``block_on_findings`` rules. Pass the output of
        ``run_detectors`` over the chain so far.
        """
        fields: dict[str, Any] = {
            "tool_name": tool_name,
            "tool_args": tool_args or {},
            **extra,
        }
        if self._containment is None:
            return self._emit(StepKind.TOOL_START, fields)

        verdict = self._containment.evaluate(
            tool_name=tool_name,
            tool_args=tool_args,
            prior_findings=prior_findings if prior_findings is not None else self._prior_findings,
        )
        if verdict.decision == Decision.ALLOW:
            return self._emit(StepKind.TOOL_START, fields)

        # Both BLOCK and STEP_UP write a tool_start record with blocked=True
        # so the chain captures the attempt for forensic posterity. The
        # difference is whether the action can be resumed via approve().
        fields["blocked"] = True
        fields["blocked_reason"] = verdict.reason
        if verdict.decision == Decision.STEP_UP:
            assert verdict.challenge_id is not None
            fields["challenge_id"] = verdict.challenge_id
            self._pending[verdict.challenge_id] = {
                "tool_name": tool_name,
                "tool_args": tool_args or {},
                "extra": extra,
            }
            self._emit(StepKind.TOOL_START, fields)
            raise StepUpRequiredError(
                verdict.reason,
                challenge_id=verdict.challenge_id,
                tool_name=tool_name,
            )
        # Decision.BLOCK
        self._emit(StepKind.TOOL_START, fields)
        raise BlockedActionError(verdict.reason, tool_name=tool_name)

    def tool_end(self, *, tool_output: str, **extra: Any) -> AgDRRecord:
        """Tool returned ``tool_output``."""
        return self._emit(StepKind.TOOL_END, {"tool_output": tool_output, **extra})

    def agent_finish(self, *, final_output: str, **extra: Any) -> AgDRRecord:
        """Agent run completed with ``final_output``."""
        return self._emit(StepKind.AGENT_FINISH, {"final_output": final_output, **extra})

    def agent_message(
        self,
        *,
        source_agent_id: str,
        target_agent_id: str,
        message_content: str,
        message_id: str | None = None,
        **extra: Any,
    ) -> AgDRRecord:
        """Inter-agent message from ``source_agent_id`` to ``target_agent_id``.

        Emits an ``agent_message`` record that the ASI07 detector (OWASP Top 10
        for Agentic Applications, Insecure Inter-Agent Communication) walks to
        check for missing identity, missing nonces, sender/key mismatch, replay,
        and protocol downgrade across inter-agent exchanges.

        ``message_id`` is a per-message nonce. When omitted, a UUIDv7 is
        generated so replay defense is on by default; callers that carry their
        own protocol's message id should pass it through.
        """
        resolved_id = message_id if message_id is not None else _uuid7()
        return self._emit(
            StepKind.AGENT_MESSAGE,
            {
                "source_agent_id": source_agent_id,
                "target_agent_id": target_agent_id,
                "message_content": message_content,
                "message_id": resolved_id,
                **extra,
            },
        )

    # -- Internal ---------------------------------------------------------

    @property
    def signer(self) -> Signer:
        """The chain signer this recorder writes through.

        Exposed so an :class:`AnchoringOrchestrator` can sign anchor
        records onto the same chain rather than starting a parallel one.
        """
        return self._signer

    @property
    def orchestrator(self) -> AnchoringOrchestrator | None:
        return self._orchestrator

    def update_findings(self, findings: list[Finding]) -> None:
        """Refresh the detector-finding state the containment policy reads.

        Operators that run detectors continuously (every N steps) call
        this with the latest findings list so ``block_on_findings`` rules
        see them on the next tool_start.
        """
        self._prior_findings = list(findings)

    def approve(self, challenge_id: str, auth0_token: str) -> AgDRRecord:
        """Verify a step-up approval token and resume the halted action.

        Validates ``auth0_token`` against the configured ``Auth0Verifier``,
        writes a ``HUMAN_APPROVAL`` record carrying the verified claims
        and the original signed token (for offline re-verification),
        then re-emits the originally-halted tool_start as a real (non-
        blocked) record. The agent that was awaiting approval now
        resumes with that record's step_id.

        Raises ``ApprovalInvalidError`` if the token does not verify or
        ``ChallengeNotFoundError`` if no pending challenge matches.
        Both leave the action permanently halted; an attacker submitting
        a forged token cannot drive the agent forward.
        """
        if self._auth0 is None:
            raise ChallengeNotFoundError(
                "no Auth0Verifier configured; pass auth0_verifier= to AIRRecorder",
            )
        if challenge_id not in self._pending:
            raise ChallengeNotFoundError(
                f"challenge {challenge_id!r} is not pending; either expired, "
                "already resolved, or never issued",
            )
        claims = self._auth0.verify(auth0_token)

        approval = HumanApproval(
            challenge_id=challenge_id,
            decision="approve",
            approver_sub=claims.sub,
            approver_email=claims.email,
            issuer=claims.issuer,
            audience=claims.audience,
            token_jti=claims.jti,
            issued_at=claims.issued_at,
            expires_at=claims.expires_at,
            signed_token=auth0_token,
        )
        approval_record = self._emit(
            StepKind.HUMAN_APPROVAL,
            {
                "challenge_id": challenge_id,
                "human_approval": approval,
            },
        )
        # Resume the halted action with a fresh non-blocked TOOL_START.
        pending = self._pending.pop(challenge_id)
        resumed_fields: dict[str, Any] = {
            "tool_name": pending["tool_name"],
            "tool_args": pending["tool_args"],
            **pending["extra"],
        }
        self._emit(StepKind.TOOL_START, resumed_fields)
        return approval_record

    def attach_orchestrator(self, orchestrator: AnchoringOrchestrator) -> None:
        """Wire an :class:`AnchoringOrchestrator` to this recorder.

        Construct the orchestrator with this recorder's ``signer`` and
        ``transports`` so anchor records chain forward correctly and land
        on the same disk file::

            recorder = AIRRecorder("chain.jsonl")
            orchestrator = AnchoringOrchestrator(
                signer=recorder.signer,
                transports=recorder.transports,
                rfc3161_client=RFC3161Client(),
                rekor_client=RekorClient(signing_key=load_anchoring_key()),
            )
            recorder.attach_orchestrator(orchestrator)

        Calling twice is a no-op except the most recent orchestrator wins.
        """
        self._orchestrator = orchestrator
        orchestrator.register_atexit()

    def _emit(self, kind: StepKind, fields: dict[str, Any]) -> AgDRRecord:
        if self._user_intent and "user_intent" not in fields:
            fields = {**fields, "user_intent": self._user_intent}
        payload = AgDRPayload.model_validate(fields)
        record = self._signer.sign(kind=kind, payload=payload)
        for transport in self._transports:
            transport.emit(record)
        if self._orchestrator is not None:
            self._orchestrator.observe_step(record)
        return record
