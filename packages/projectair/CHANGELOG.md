# Changelog

All notable changes to `projectair` are documented here. Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Versioning: [SemVer](https://semver.org/).

## [0.9.0] - 2026-05-12

**Status: beta (NVIDIA integrations).** Full NVIDIA AI safety stack integration: NeMo Guardrails telemetry, NemoGuard NIM classifiers, and cross-corroboration with AIR's heuristic detector pipeline.

### Added
- `instrument_nemo_guardrails`: wraps `nemoguardrails.LLMRails` to capture every activated rail (input/output/dialog/generation) and every LLM call the guardrails engine makes as signed capsule records. Supports `generate` and `generate_async`.
- `NemoGuardClient`: wraps all three NVIDIA NemoGuard NIM classifiers (JailbreakDetect `/v1/classify`, ContentSafety `/v1/completions`, TopicControl `/v1/chat/completions`) with signed `tool_start`/`tool_end` capsule pairs per classification. Supports hosted (build.nvidia.com) and self-hosted NIM endpoints via configurable URLs and API key.
- **AIR-05 NemoGuard Safety Classification** detector: standalone findings when NemoGuard classifiers flag unsafe content. Severity scales with safety category (S1/S3/S7/S17/S22 = critical, others = high, topic control = medium).
- **AIR-06 NemoGuard Corroboration** detector: cross-corroboration between AIR heuristic detectors and NemoGuard NIM classifiers. When AIR-01 flags prompt injection and NemoGuard JailbreakDetect independently agrees within 5 steps, emits a critical corroboration finding. Maps: jailbreak -> AIR-01, content_safety -> AIR-01/AIR-02/ASI09, topic_control -> ASI01.
- NemoGuard `tool_end` records now carry structured extra fields (`nemoguard_classifier`, `nemoguard_safe`, `nemoguard_score`, `nemoguard_categories`) for clean detector consumption.
- Detector count: 10 OWASP Agentic + 3 OWASP LLM + 3 AIR-native = **16 total**.

## [0.8.1] - 2026-05-11

### Added
- `--from` / `--to` date-range filtering on `air report article72`, `air report nist-rmf`, and `air report soc2-ai`. The full chain is verified for integrity first; only records within the date window are passed to detectors and the report generator. Both flags accept ISO dates (YYYY-MM-DD) and are inclusive on both ends.

## [0.8.0] - 2026-05-11

**Status: experimental (ML-DSA-65).** Post-quantum signing and package metadata update.

### Added
- **ML-DSA-65 (FIPS 204) post-quantum signatures**, opt-in experimental. `Signer.generate(algorithm=SigningAlgorithm.ML_DSA_65)` or `AIRRecorder(..., signing_algorithm=SigningAlgorithm.ML_DSA_65)`. Requires `cryptography>=48.0.0`. Ed25519 remains the default. Mixed-algorithm chains (some records Ed25519, some ML-DSA-65) verify correctly. AgDR schema bumped to **0.5** (adds `signature_algorithm` field; v0.4 records without the field default to `"ed25519"` and verify unchanged).

### Changed
- Package author metadata updated to Kevin Minn <support@vindicara.io>.

## [0.7.1] - 2026-05-07

Pricing alignment release. The `air upgrade` CLI command now reflects the public pricing on https://vindicara.io/pricing.

### Changed
- `air upgrade` output: Individual tier price moved from $29/mo to $39/mo. Team tier now shows the flat public price ($599/mo) instead of "Talk to us"; Enterprise remains custom because it depends on volume, deployment model, and add-ons (SSO, SLA, BAA, insurance integrations).

## [0.7.0] - 2026-05-07

**Status: Wave 1 alpha.** Layer 4 Wave 1: AgDR Handoff Protocol (A2A) for cross-agent chain of custody. Layers 1-3 secure a single agent; Layer 4 secures the boundary between agents. When Agent A delegates to Agent B, the cryptographic chain survives the handoff: a Parent Trace ID (W3C trace_id verbatim) propagates through capability tokens and HTTP headers, a HANDOFF record at the source pairs cryptographically with a HANDOFF_ACCEPTANCE record at the target, and a Sigstore Rekor counter-attestation with hashed identifiers proves Agent B actually validated the capability token without leaking workflow topology to the public log.

Wave 1 ships single-tenant + synchronous Rekor mode + the full eight-step verifier. Wave 2 lifts the cross-tenant feature flag once Wave 1 has at least one reference deployment. v1.5 ships private/enterprise federation (custom CA roots, archived JWKS).

**Public proof point:** Wave 1 was demonstrated live against a real Auth0 tenant (`dev-kilt2vkudvbu75ny.us.auth0.com`) on 2026-05-07. The capability token was minted by Auth0's `/oauth/token` endpoint with the four `air_*` custom claims injected by an Auth0 Action attached to the M2M / Client Credentials Exchange trigger. The validation attestation is anchored on the public Sigstore Rekor at log index **1465403522** (https://search.sigstore.dev/?logIndex=1465403522). The Rekor entry contains hashed identifiers only — auditors with chain access can resolve the hashes to cleartext; the public log reveals no agent topology.

### Added
- `airsdk.handoff.canonicalize`: RFC 8785 JCS canonicalization wrapper over the `jcs` library, with a strict JSON-primitive input policy (Section 15.11). Rejects bytes / datetime / UUID / Decimal / Enum / pathlib / tuple inputs with a JSONPath-style diagnostic so callers fix the offending field rather than silently locking a cross-language interoperability bug into a permanent Sigstore Rekor anchor. Three canonical empty-payload conventions (`BLAKE3(b"")`, `BLAKE3(b"{}")`, `BLAKE3(b"[]")`) are distinct, not interchangeable.
- `airsdk.handoff.trace`: W3C Trace Context generation, parsing, and propagation. `generate_ptid` mints a 32-lowercase-hex W3C trace_id; `parse_traceparent` is a strict parser (rejects all-zero IDs, version `ff`, malformed shapes); `child_context` derives a fresh span-id while preserving trace-id and trace-flags; `reconcile_channels` fails closed when JWT `air_ptid`, W3C `traceparent`, and `Air-Parent-Trace-Id` channels disagree on the trace-id.
- `airsdk.handoff.identity`: `IdentityFormat` enum (`sigstore_fulcio` / `x509_pem` / `local_dev`), `AgentIdentity` dataclass with Ed25519 signing key, and `generate_local_dev_identity` for Wave 1 demos. The verifier flags chains using LOCAL_DEV identities so operators know they are not anchored to a real CA root.
- `airsdk.handoff.handoff_record`: `agdr/v2.handoff` and `agdr/v2.handoff_acceptance` record builders (Sections 6.2 / 6.3). Each record is JCS-canonicalized for content_hash and Ed25519-signed over `prev_hash || content_hash`. Tampering breaks the content_hash check; wrong key fails the signature check.
- `airsdk.handoff.idp.IdPAdapter`: abstract base class declaring `handled_issuers`, `issue_capability_token`, `verify_capability_token`, and `discover_metadata`. Mints + verifies JWTs carrying the four required `air_*` claims (`air_ptid`, `air_delegation_payload_hash`, `air_protocol_version`, `air_target_idp_issuer`).
- `airsdk.handoff.idp.AdapterRouter`: explicit `iss`-to-adapter routing per Section 8.4. Duplicate registrations are rejected; unregistered issuers raise `UnregisteredIssuerError` rather than silently falling back to OIDC discovery against an unknown issuer (which would let an attacker inject a malicious issuer URL).
- `airsdk.handoff.idp.Auth0Adapter`: reference RS256/JWKS implementation. Local-signing mode (PEM + kid) for Wave 1 demos and tests; production mode (`/oauth/token` + Auth0 Action) is the documented deployment path. The Auth0 Action that injects the four `air_*` custom claims is included in the spec; without it Auth0 strips the parameters and verification hard-fails with `CustomClaimMissingError`.
- `airsdk.handoff.idp.OktaAdapter`, `EntraAdapter`, `SpiffeAdapter`: interface-only placeholders that raise `IdPNotImplementedError` on construction. Signal to enterprise prospects that the protocol is IdP-agnostic; the adapters ship in v1.5 alongside enterprise federation.
- `airsdk.handoff.validation_proof`: Rekor counter-attestation per Section 6.4. The attestation blob hashes every human-readable identifier (agent ID, JTI, issuer URL, PTID) so the public Rekor log carries zero workflow topology metadata. Wave 1 ships synchronous mode only; async-with-retry and local-signed-only modes ship in 0.7.1. `StubRekorBackend` for unit tests; `LiveRekorBackend` wraps the Layer 1 `RekorClient` for real submission.
- `airsdk.handoff.verifier`: eight-step `CrossAgentVerifier` per Section 8.2. Step 1 PTID consistency, step 2 root identification, step 3+4 handoff/acceptance pairing with hard-fail replay-anomaly check (`ReplayAnomalyError`), step 5 capability token routing via `AdapterRouter`, step 5b Rekor proof verification, step 6 intra-chain integrity, step 7 two-bound temporal ordering math (Section 15.15 — naive `>` comparison is explicitly forbidden), step 8 identity cert validation. `verify_temporal_ordering` is the canonical reference implementation; lower-bound failures distinguish "receiver clock lagging sender" from "acceptance arrived after timeout".
- `air handoff verify --ptid <ptid> --chain <path> ...`: minimum-viable CLI subcommand. Runs the eight-step verifier and exits non-zero on failure; full subcommand suite (`trace`, `graph`, `emit-test`, `validate-proof`, `rekor-queue`) ships incrementally per Section 9.1.
- 56 new tests in `tests/handoff/`: JCS roundtrip + reference values, three empty-payload conventions distinct, strict input policy rejecting datetime / bytes / Decimal / tuple, W3C traceparent strict parsing, channel-disagreement fail-closed, handoff record build/sign/verify and tamper detection, intent-redaction roundtrip, Auth0Adapter issue/verify/wrong-audience/wrong-PTID/missing-air-claim cases, AdapterRouter unknown-issuer rejection, validation proof hashed-identifier rule and tamper detection, replay-anomaly hard-fail in the verifier, two-bound temporal ordering with skew tolerance.
- `scripts/e2e_layer4.py`: end-to-end Wave 1 demo. Spawns an in-process JWKS server, mints a capability token, EA writes a HANDOFF record, Coach validates the token + submits a Rekor counter-attestation, Coach writes a HANDOFF_ACCEPTANCE record, the verifier runs the eight steps and prints PASS. `--live-rekor` flag submits to the public Sigstore Rekor.

### Notes
- Path B mixed-record file: handoff and acceptance records live alongside the v0.4 AgDR records in the same JSONL chain. The Layer 4 wire format uses its own `schema` field (`agdr/v2.handoff`, `agdr/v2.handoff_acceptance`, `agdr/v2.validation_attestation`) and is independent of the existing v0.4 record schema; legacy chain integrity remains unchanged.
- 406 tests pass (350 pre-existing + 56 new); mypy --strict clean across the new surface; ruff clean.
- Wave 2 (cross-tenant via Sigstore Fulcio + OIDC Discovery) ships once Wave 1 has at least one reference deployment.

## [0.6.1] - 2026-05-07

Auth0 wedge integration. 0.6.0 shipped the JWT verifier and the recorder hook; that gave you the primitive but not the integration. This release closes the gap so an OSS user with their own Auth0 tenant can wire the end-to-end step-up flow without writing custom OAuth code.

### Added
- `airsdk.containment.Auth0Tenant` config dataclass: domain, audience, optional client_id, optional scope. Derives `issuer`, `authorize_url`, `token_url`, `device_code_url`, and `jwks_uri` so callers do not stringify URLs by hand.
- `airsdk.containment.build_authorize_url(tenant, challenge_id, redirect_uri, *, code_challenge=None)`: constructs a well-formed Auth0 `/authorize` URL for the browser flow. The challenge_id is bound to the OAuth `state` parameter so the redirect callback can match the returning code to the originally-halted action. PKCE supported via `code_challenge` argument.
- `airsdk.containment.make_pkce_pair()`: RFC 7636 verifier+challenge generator for native CLI tools and SPAs (Auth0 requires PKCE for those).
- `airsdk.containment.start_device_flow(tenant)`: OAuth 2.0 Device Authorization Grant (RFC 8628) initiator. Returns `DeviceAuthorization(device_code, user_code, verification_uri, verification_uri_complete, expires_in, interval)` for headless agents.
- `airsdk.containment.poll_device_token(tenant, device_code, *, interval, max_poll_seconds)`: blocks polling Auth0's token endpoint, handling `authorization_pending`, `slow_down`, `access_denied`, `expired_token`, and timeout. Returns the raw JWT on success.
- `airsdk.containment.Auth0DeviceFlowError`: distinct from `ApprovalInvalidError`. Token-verification failures get the latter; "user never finished the flow" gets the former.
- `air approve` CLI with three modes:
  - `--token <jwt>`: caller already has a verified Auth0 access token; submit it.
  - `--device --client-id <id>`: run the device flow; CLI prints user code + verification URL, polls until done, submits the token.
  - `--authorize-url --client-id <id> --redirect-uri <uri>`: print the Auth0 `/authorize` URL with PKCE for browser-based flows; receiving service swaps the code and re-runs `air approve --token`.
  - `--jwks-uri` and `--issuer` overrides for testing against local IdPs.
- 18 new tests in `tests/containment/test_auth0_flows.py` and `tests/containment/test_approve_cli.py`: tenant URL derivation, authorize-URL parameter shape with and without PKCE, PKCE round-trip vs RFC 7636, device-flow request shape, polling through `authorization_pending` then success, denial / expiry / timeout handling, CLI mode-selection validation, end-to-end CLI approval against the in-process mock IdP.

### Operational note
The CLI runs in a different process from the agent that raised `StepUpRequiredError`. Only the chain on disk is shared. `air approve` verifies the token, appends a `HUMAN_APPROVAL` record to the chain, and lets the agent process pick up the approval on its next chain reload. For in-process flows (single agent + operator) call `recorder.approve(challenge_id, token)` directly.

## [0.6.0] - 2026-05-07

Layer 3 (Containment with Auth0-verified human-in-the-loop) v1. Layer 1 lets a verifier prove what happened. Layer 2 lets an analyst explain why. Layer 3 stops the bad thing from happening — and binds the chain to the authenticated human who authorized any action that needed step-up approval. The chain is no longer just an audit trail; it is a consent record.

### Added
- `airsdk.containment.ContainmentPolicy` declarative ruleset: `deny_tools` (block by name), `deny_arg_patterns` (block by argument regex), `block_on_findings` (halt after a guard detector fires), `step_up_for_actions` (require human approval for matched actions). Deny rules override step-up rules so "absolutely never" stays absolute even when an operator forgets to remove a step-up rule for the same tool.
- `airsdk.containment.Auth0Verifier` — real RS256/RS384/RS512 JWT verification using PyJWT's `PyJWKClient` against an issuer's published JWKS. Validates signature, issuer, audience, expiration, and presence of `sub`. Raises `ApprovalInvalidError` on any failure. Named for Auth0 because that is the documented integration target, but the implementation is generic OIDC + JWKS and accepts any compliant IdP (Okta, Azure AD, Google Workspace).
- New `StepKind.HUMAN_APPROVAL` carries the verified `Auth0Claims` (`sub`, `email`, `iss`, `aud`, `iat`, `exp`, `jti`) plus the original signed JWT for offline re-verification. AgDR schema bumps 0.3 → 0.4.
- `AIRRecorder` accepts `containment=` and `auth0_verifier=`. `tool_start` consults the policy before any side effect. Three outcomes: allow (normal record), block (write blocked TOOL_START + raise `BlockedActionError`), or step-up (write blocked TOOL_START with a `challenge_id` + raise `StepUpRequiredError`).
- `AIRRecorder.approve(challenge_id, auth0_token)` — validates the token, records `HUMAN_APPROVAL`, then re-emits the originally-halted tool_start as a fresh non-blocked record. Forged or wrong-issuer tokens leave the action permanently halted; an attacker submitting a bad token cannot drive the agent forward.
- `scripts/e2e_layer3.py` — runnable nine-stage demo: replays the SSH-exfil narrative through a recorder configured with step-up-on-`http_post`, halts at the exfiltration step, validates a JWT minted against an in-process mock IdP (real PyJWT verification path, not stubbed), records the approval, and confirms the resumed `http_post` lands as a non-blocked record.
- 24 new tests in `tests/containment/`: policy rule precedence (deny > step-up), Auth0Verifier rejecting forged signatures / wrong audience / wrong issuer / expired / missing `sub`, end-to-end recorder integration including the forged-token-cannot-resume case.

### Changed
- `tool_start` now accepts `prior_findings=` so an operator running detectors continuously can pass the latest findings list directly. `update_findings(findings)` updates the recorder-side state for `block_on_findings` rules between tool calls.
- New runtime dep `PyJWT[crypto]>=2.8`. The `[crypto]` extra pulls in `cryptography` for RSA verification (already a dep).

### Compliance positioning
- The `HUMAN_APPROVAL` record binds an action to the authenticated human who authorized it, with the signed token preserved on-chain. This maps directly to: EU AI Act Article 14 (human oversight obligations), GDPR Article 22 (automated decision-making with human intervention), SOC 2 access controls (authenticated approval of sensitive operations). The chain becomes admissible evidence not just of what the agent did but of who consented to what the agent did.

### Deferred
- Hosted approval router and tenant management (challenge dispatch, push notifications, fleet dashboard, audit reports): commercial `projectair-pro` tier. The MIT package ships the primitive; the wedge integration ships in pro.
- LangChain / OpenAI tool-call interceptor wrappers (so containment kicks in automatically without manual `tool_start` calls): planned for v0.7 alongside other framework integration polish.
- A2A multi-agent containment (one agent halts another agent's request via the same flow): tracked separately as A2A protocol work.

## [0.5.0] - 2026-05-07

Layer 2 (Causal Reasoning) v1. Layer 1 lets a verifier prove what happened. Layer 2 lets an analyst explain *why* it happened. The new `airsdk.causal` module walks an AgDR chain, infers step-to-step dependencies, and surfaces the load-bearing records as a narrowed evidence excerpt.

### Added
- `airsdk.causal.build_causal_graph(records)` builds a `CausalGraph` from any AgDR chain. Edges split into hard (CHAIN_LINK, LLM_PAIR, TOOL_PAIR, LLM_DECISION, AGENT_MESSAGE) at confidence 1.0 and soft (OUTPUT_REUSE) with length-based confidence in [0.5, 1.0]. The hard/soft distinction is the trust contract: an analyst can rely on hard edges in a report and treat soft edges as supporting context.
- `airsdk.causal.explain_step(graph, target)` and `airsdk.causal.explain_finding(graph, findings, detector_id)` produce narrowed `Explanation` objects: chronological lists of the load-bearing records and the edges connecting them. Depth-bounded (default `max_depth=4`) so dense causal chains do not pull every prior record into every explanation.
- `air explain` CLI command. Two modes: `--step <ordinal-or-uuid>` and `--finding <detector_id>`. Output is intentionally short — a forensic analyst sees the 5-7 records that mattered, marked hard or soft, and walks away with a story they can put in a report.
- New test fixture: `tests/causal/test_inference.py` and `tests/causal/test_explain.py` exercise the SSH-exfiltration demo chain (`_concrete_demo.py`) end to end. Inference test asserts the two critical OUTPUT_REUSE edges (poisoned README → next prompt, leaked SSH key → http_post body) appear at high confidence and that no spurious soft edges land. Explanation test asserts the explanation set is exactly `{2, 3, 4, 5, 6, 7, 8}` for the exfiltration step, with pre-attack setup (0, 1) and post-outcome (9) excluded.

### Changed
- Detector engine now also drives Layer 2 explanations. `air explain --finding ASI02` re-runs `run_detectors` against the chain, gathers the flagged step ids, and walks each one's causal ancestry. No detector code changed.

### Deferred
- `air query` DSL (Q3 2026 per the Layer 1 spec). CLI flags suffice for v1; a full DSL is a parser/AST/evaluator surface that does not yet earn its keep.
- Counterfactual replay (Q4 2026 per the spec). Requires re-running the agent with mutated inputs — out of scope for v1, foundation (the causal graph) lands here.
- Graph visualization (`air explain --graph`). Text output is the deliverable; rendering is a v2 nice-to-have.

## [0.4.0] - 2026-05-06

Layer 1 (External Trust Anchor) v1. Project AIR chains can now bind their root to two independent public proofs so the chain is verifiable without trusting Vindicara, the customer, or the agent vendor.

**Live verification proof.** A reference chain produced by `scripts/e2e_layer1.py` was anchored to the public Sigstore Rekor on 2026-05-07 and verified via `air verify-public` from a clean subprocess environment. The Rekor entry is at log index **1455601514** (https://search.sigstore.dev/?logIndex=1455601514) with FreeTSA timestamp `2026-05-07T01:03:40Z` over BLAKE3 chain root `ea91028138e618765b7ab3a374bf7d947c760dc1d894009760277de8e8bb2d9f`. Anyone can pull that entry from public infrastructure and confirm it independently.

### Added
- `airsdk.anchoring.RFC3161Client`: submits chain root hashes to a Time Stamping Authority and parses the returned `TimeStampToken`. Uses `rfc3161-client` for ASN.1 + verification. Defaults to FreeTSA; DigiCert, GlobalSign, and Sectigo are also supported via the `tsa_url` argument. Distinguishes 429 (rate limited) from other failures via `TSARateLimitedError` and emits a WARNING log so operators running fleets can see when public TSAs throttle them; the default 10-second cadence translates to ~360 requests/hour per process, and a fleet on FreeTSA can trip the limiter. Pin a paid TSA via `tsa_url=` for production scale.
- `airsdk.anchoring.RekorClient`: submits chain roots as `hashedrekord` entries to a Sigstore Rekor transparency log. Uses raw ECDSA P-256 keys (no Fulcio cert required). Verifies the returned Merkle inclusion proof immediately and stores both the entry payload and the proof in the anchor record so verifiers can re-check offline. The signature is ECDSA P-256 over the raw 32-byte SHA-256 hash using **Prehashed** semantics (no further hashing at sign time): empirically verified against live `rekor.sigstore.dev` entries. Ed25519 was the original choice and is in the rekor-types schema, but `rekor.sigstore.dev` does not actually exercise Ed25519 hashedrekord verification in production; ECDSA P-256 is the path Rekor verifies cleanly.
- `airsdk.anchoring.AnchoringOrchestrator`: decides when to anchor (default every 100 steps OR every 10 seconds) and what to do on TSA/Rekor failure. Configurable `FailurePolicy` supports per-action fail-closed overrides for high-value tools alongside a default `fail_open` posture. Three layers of recovery (background emit, atexit best-effort flush, on-disk catch-up via `hydrate_from_chain`) guarantee that no step is silently dropped across SIGKILL or power loss.
- `air anchor`, `air verify`, and `air verify-public` CLI commands. `air verify-public` runs the five-step verification flow using only public infrastructure with zero Vindicara API calls.
- `airsdk.anchoring.identity.load_anchoring_key`: per-install Ed25519 anchoring identity, loaded from `AIRSDK_ANCHORING_KEY` env, or `~/.config/projectair/anchoring_key.pem` (mode 0600), or generated on first use.
- `StepKind.ANCHOR` and matching anchor metadata (`anchored_chain_root`, `anchored_step_range`, `rfc3161`, `rekor`) on `AgDRPayload`. AgDR `version` advances to `0.3`.

### Changed
- `FileTransport.emit` now calls `os.fsync` after every record so the chain on disk survives power loss; this is what makes the orchestrator's chain-as-spool recovery model sound. Measured overhead on macOS APFS: ~5% (~9,000 vs ~9,500 records/sec, ~0.11 vs ~0.10 ms/record per `scripts/bench_fsync.py`). On Linux ext4/xfs with real `fsync` semantics expect 50-200 us per record on NVMe and noticeably more on rotational disks; agents emitting >1,000 steps/sec on a Linux HDD should benchmark before deploying. Note that macOS `os.fsync` does not force the platter write (the strong sync is `fcntl(fd, F_FULLFSYNC)`, not yet wired); on macOS the durability guarantee is weaker than on Linux until that lands. Agents that need maximum throughput at the cost of weaker crash recovery can opt out via `FileTransport(path, fsync=False)`. A future release will add `fsync_mode={every,batch,off}` so operators can pick batched durability without losing recovery entirely.
- Public framing for the chain stays "Signed Intent Capsule." Layer 1 is described as "verifiable independently using public infrastructure" rather than "court-admissible" until the cryptography audit returns.

### Deferred to follow-up releases
- Live FreeTSA / Rekor integration tests are written and gated by `@pytest.mark.network`; a recurring CI job will run them.
- Bundled TSA root certificate set, README/homepage rewrite, `docs/anchoring.md`, `docs/threat-model.md`, real-chain blog post, and Loom video. The code path supports them; the marketing surface ships next.
- ML-DSA-65 post-quantum hybrid signatures (Layer 1 v2, planned Q3 2026).
- Notary co-signing network (Layer 1 v3, 2027).
- Anchoring key rotation with key transparency log (planned v0.4.1).

## [0.3.2] - 2026-05-01

### Added
- Google Gemini SDK integration: `airsdk.integrations.gemini.instrument_gemini(client, recorder)`. Wraps a `google.genai.Client` as a transparent proxy that emits signed `llm_start` + `llm_end` Intent Capsules for every `models.generate_content`, `chats.send_message`, and corresponding `aio.*` async call. Streaming helpers in `airsdk.integrations._gemini_streams` capture incremental responses without buffering the whole stream. Anything outside the LLM surface (`client.files`, `client.tunings`, `client.batches`) passes through unchanged.
- Google ADK integration: `airsdk.integrations.adk.instrument_adk(agent, recorder)` and `airsdk.integrations.adk.make_air_callbacks(recorder)`. Attaches AIR callbacks to a constructed `LlmAgent` via the four ADK callback hooks (`before_model_callback`, `after_model_callback`, `before_tool_callback`, `after_tool_callback`). Records before chaining to any user-supplied callback so existing short-circuit / replace logic is preserved. List-form callbacks are honoured.
- `examples/gemini_demo.py` and `examples/adk_demo.py`: end-to-end runnable demos against `gemini-2.5-flash` that record a single agent turn, verify the resulting Signed Intent Capsule chain, and print the public verification key.

### Verified
- OpenAI-compatible endpoints (NVIDIA NIM, vLLM, TGI, Together AI, Groq, Mistral, Fireworks) work via the existing `instrument_openai` integration with no NIM-specific code path. Verified by network-gated E2E test at `tests/test_integrations_nim_e2e.py` and runnable demo at `examples/nim_demo.py`.

## [0.3.1] - 2026-04-23

### Added
- LlamaIndex LLM integration: `airsdk.integrations.llamaindex.instrument_llamaindex(llm, recorder)`. Wraps any `llama_index.core.llms.LLM` subclass as a transparent proxy that emits signed `llm_start` + `llm_end` Intent Capsules for every `complete` / `acomplete` / `stream_complete` / `astream_complete` / `chat` / `achat` / `stream_chat` / `astream_chat` call. Tool-call content on chat responses is captured in the `llm_end` payload. Every other attribute passes through unchanged, so the wrapped object drops into LlamaIndex query engines, chat engines, and agents wherever a plain LLM is expected.

## [0.3.0] - 2026-04-22

### Added
- ASI03 Identity & Privilege Abuse detector: Zero-Trust-for-agents enforcement via operator-declared `AgentRegistry` (identity forgery, unknown agent, out-of-scope tool, privilege-tier escalation).
- ASI10 Rogue Agents detector: Zero-Trust behavioral-scope enforcement via declared `BehavioralScope` (unexpected tool, fan-out breach, off-hours activity, session tool budget).
- `air report article72` command: EU AI Act Article 72 post-market monitoring Markdown template generation.
- `AgentRegistry`, `AgentDescriptor`, `BehavioralScope` pydantic schemas exported from the top-level `airsdk` package.

### Changed
- Public OWASP coverage framing is now "10 OWASP Agentic + 3 OWASP LLM + 1 AIR-native." `UNIMPLEMENTED_DETECTORS` is empty.

## [0.2.4] - 2026

### Added
- ASI08 Cascading Failures detector: oscillating-pair threshold (4 cycles) + fan-out threshold (5 distinct targets within 10-record window) over `agent_message` records.

## [0.2.3] - 2026

### Added
- ASI05 Unexpected Code Execution detector: tool-name / argument pattern match for execution semantics (eval, exec, shell).
- ASI09 Human-Agent Trust Exploitation detector: fabricated-rationale and manipulation-language scan preceding sensitive actions.

## [0.2.1] - 2026

### Added
- ASI06 Memory & Context Poisoning detector (heuristic: retrieval-output + memory-write scans).
- ASI07 Insecure Inter-Agent Communication detector (identity, nonce, replay, downgrade, descriptor-forgery checks over `agent_message` records).

## [0.1.x] - 2026

### Added
- Initial public release. BLAKE3 + Ed25519 Signed Intent Capsule chain (AgDR-compatible format). Chain verification and tamper detection. LangChain callback handler (`AIRCallbackHandler`). OpenAI SDK integration (`instrument_openai`). Anthropic SDK integration (`instrument_anthropic`). ASI01 Agent Goal Hijack, ASI02 Tool Misuse & Exploitation, and partial ASI04 Agentic Supply Chain (MCP only) detectors. AIR-01 Prompt Injection (OWASP LLM01), AIR-02 Sensitive Data Exposure (OWASP LLM06), AIR-03 Resource Consumption (OWASP LLM04), AIR-04 Untraceable Action (AIR-native). JSON, PDF, and SIEM (ArcSight CEF v0) forensic exports. `air` Typer CLI with `demo`, `trace`, `report` commands.
