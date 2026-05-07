# Changelog

All notable changes to `projectair` are documented here. Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Versioning: [SemVer](https://semver.org/).

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
