# Changelog

All notable changes to `projectair` are documented here. Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Versioning: [SemVer](https://semver.org/).

## [0.4.0] - 2026-05-06

Layer 1 (External Trust Anchor) v1. Project AIR chains can now bind their root to two independent public proofs so the chain is verifiable without trusting Vindicara, the customer, or the agent vendor.

### Added
- `airsdk.anchoring.RFC3161Client`: submits chain root hashes to a Time Stamping Authority and parses the returned `TimeStampToken`. Uses `rfc3161-client` for ASN.1 + verification. Defaults to FreeTSA; DigiCert, GlobalSign, and Sectigo are also supported via the `tsa_url` argument. Distinguishes 429 (rate limited) from other failures via `TSARateLimitedError` and emits a WARNING log so operators running fleets can see when public TSAs throttle them; the default 10-second cadence translates to ~360 requests/hour per process, and a fleet on FreeTSA can trip the limiter. Pin a paid TSA via `tsa_url=` for production scale.
- `airsdk.anchoring.RekorClient`: submits chain roots as `hashedrekord` entries to a Sigstore Rekor transparency log. Uses raw Ed25519 signatures (no Fulcio cert required). Verifies the returned Merkle inclusion proof immediately and stores both the entry payload and the proof in the anchor record so verifiers can re-check offline.
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
