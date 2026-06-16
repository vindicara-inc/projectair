# CLAUDE.md

Project AIR by Vindicara: forensic accountability SDK for AI agents. MIT CLI (`air`) + library (`airsdk`) on PyPI as `projectair`. Five-layer architecture: detection, anchoring, causal reasoning, containment, cross-agent trust, data governance.

## Brand hierarchy

## Current state (2026-05-10)

Brand hierarchy:
- Company: Vindicara
- Flagship initiative (external-facing, gravity surfaces): Project AIR
- Product tier names (developer-facing, light surfaces): AIR SDK, AIR Cloud, AIR Enterprise
- Technical artifacts (package names, imports, CLI): `air`, `airsdk`, `vindicara`

Rule: use "Project AIR" on hero pages, pitch decks, whitepapers, legal documents, press, investor materials. Use "AIR" in code, docs, CLI, and technical copy where brevity matters.

The AIR pivot shipped. The OSS promise is live on PyPI. Read this before doing anything substantive.

### On PyPI

- `projectair` **0.7.1** is the latest live release (published 2026-05-07). MIT. Ships the `air` CLI and the `airsdk` library. This is the public product. The four-layer architecture is now complete: detector coverage (Layer 0) + external trust anchor (Layer 1) + causal reasoning (Layer 2) + Auth0-verified containment (Layer 3) + AgDR Handoff Protocol Wave 1 (Layer 4). 0.7.1 itself is the pricing-alignment bump (`air upgrade` now reflects the public Individual $39/mo and flat Team $599/mo prices).
- **ML-DSA-65 (FIPS 204) post-quantum signatures** landed as opt-in experimental in the working tree (not yet released). `Signer.generate(algorithm=SigningAlgorithm.ML_DSA_65)` or `AIRRecorder(..., signing_algorithm=SigningAlgorithm.ML_DSA_65)`. AgDR schema bumped to **0.5** (adds `signature_algorithm` field; v0.4 records without the field default to `"ed25519"` and verify unchanged). Requires `cryptography>=48.0.0`. Ed25519 remains the default. Mixed-algorithm chains verify correctly. Layer 4 handoff identity is still Ed25519-only (separate scope). Mark as `experimental` in all docs until at least one customer uses it.
- Release lineage (each is a real PyPI release unless marked):
  - 0.1.0–0.1.5: initial detectors, signing, LangChain + OpenAI + Anthropic integrations.
  - 0.2.1 ASI06+ASI07; 0.2.3 ASI05+ASI09; 0.2.4 ASI08. (0.2.0 and 0.2.2 were local-only.)
  - 0.3.0 (2026-04-22): full 10 of 10 OWASP Agentic via ASI03 + ASI10 (Zero-Trust enforcement); `air report article72`.
  - 0.3.1 (2026-04-23): LlamaIndex (`instrument_llamaindex`).
  - 0.3.2 (2026-05-01): Google Gemini SDK (`instrument_gemini` over `google-genai`) + Google ADK (`instrument_adk` over `google-adk`); NVIDIA NIM verified to work via `instrument_openai`.
  - 0.4.0 (2026-05-06): **Layer 1** External Trust Anchor. RFC 3161 + Sigstore Rekor anchoring; `air anchor` / `air verify` / `air verify-public`; `FileTransport.emit` now `os.fsync`s after every record (~5% overhead on macOS APFS). Reference chain anchored on public Rekor at log index 1455601514. AgDR `version` advanced to 0.3 with `StepKind.ANCHOR`.
  - 0.5.0 (2026-05-07): **Layer 2** Causal Reasoning. `airsdk.causal.{build_causal_graph, explain_step, explain_finding}`; `air explain --step` and `air explain --finding`. Hard edges (CHAIN_LINK / LLM_PAIR / TOOL_PAIR / LLM_DECISION / AGENT_MESSAGE) at confidence 1.0; soft edges (OUTPUT_REUSE) at 0.5–1.0.
  - 0.6.0 (2026-05-07): **Layer 3** Auth0-verified containment v1. `ContainmentPolicy`, `Auth0Verifier`, `StepKind.HUMAN_APPROVAL`. AgDR schema 0.3 → **0.4**.
  - 0.6.1 (2026-05-07): `air approve` CLI (`--token`, `--device`, `--authorize-url`); device flow + PKCE + authorize-URL helpers.
  - 0.7.0 (2026-05-07): **Layer 4 Wave 1 (alpha)** AgDR Handoff Protocol (A2A). `airsdk.handoff.*`, `air handoff verify`, `agdr/v2.handoff` and `agdr/v2.handoff_acceptance` schemas. Live demo against real Auth0 tenant `dev-kilt2vkudvbu75ny.us.auth0.com`; Rekor anchor at log index 1465403522. Wave 1 is single-tenant + synchronous Rekor mode + the full eight-step verifier; Wave 2 (cross-tenant via Sigstore Fulcio + OIDC Discovery) ships once Wave 1 has at least one reference deployment.
  - 0.7.1 (2026-05-07): `air upgrade` pricing alignment (no code-path changes).
- To publish a new release: add a `[<ver>]` section to `packages/projectair/CHANGELOG.md` (Keep a Changelog format), bump `packages/projectair/pyproject.toml` + `airsdk/__init__.py`, then from `packages/projectair/`: `rm -f dist/*.whl dist/*.tar.gz && python -m build && python -m twine check dist/* && python -m twine upload dist/projectair-<ver>*`. Always `cd packages/projectair` first; running `python -m build` from the repo root produces a vindicara wheel instead.
- The simple index at `https://pypi.org/simple/projectair/` updates faster than the JSON endpoint when checking propagation. Credentials live in `~/.pypirc` (permissions `-rw-------`, username `__token__`, password is the PyPI API token starting with `pypi-`). With `~/.pypirc` in place, `twine upload` is non-interactive.
- `vindicara` 0.2.0 live, repositioned as "server-side engine behind AIR Cloud." `vindicara` 0.1.0 yanked.

### Detector coverage (honest, ground in actual OWASP specs, do not fabricate)

- OWASP **Top 10 for Agentic Applications** (**10 of 10**):
  - `ASI01` Agent Goal Hijack
  - `ASI02` Tool Misuse & Exploitation
  - `ASI03` Identity & Privilege Abuse (shipped 0.3.0; Zero-Trust-for-agents via `AgentRegistry`: identity forgery / unknown agent / out-of-scope tool / privilege-tier escalation)
  - `ASI04` Agentic Supply Chain Vulnerabilities (partial, MCP only)
  - `ASI05` Unexpected Code Execution (shipped 0.2.2)
  - `ASI06` Memory & Context Poisoning (shipped 0.2.1)
  - `ASI07` Insecure Inter-Agent Communication (shipped 0.2.0)
  - `ASI08` Cascading Failures (shipped 0.2.4; oscillating-pair threshold 4 cycles + fan-out threshold 5 distinct targets / 10-record window, operating over AGENT_MESSAGE records)
  - `ASI09` Human-Agent Trust Exploitation (shipped 0.2.3)
  - `ASI10` Rogue Agents (shipped 0.3.0; Zero-Trust behavioral-scope enforcement via `BehavioralScope`: unexpected tool / fan-out breach / off-hours activity / session tool budget)
- `UNIMPLEMENTED_DETECTORS` is now empty.
- OWASP **Top 10 for LLM Applications** (3 categories, implemented as AIR-specific detectors): `AIR-01` → LLM01 Prompt Injection, `AIR-02` → LLM06 Sensitive Information Disclosure, `AIR-03` → LLM04 Model Denial of Service.
- **AIR-native**: `AIR-04` Untraceable Action (forensic-chain-integrity check; no direct OWASP equivalent).
- Correct public framing as of 0.3.0: **"10 OWASP Agentic + 3 OWASP LLM + 1 AIR-native."** Every public claim must cite this exact taxonomy. Never revert to the "8 of 10" or "3 of 10" framing from earlier releases.
- **ASI10 is Zero-Trust enforcement, not anomaly detection.** Frame it as declared-scope enforcement in every doc, docstring, README, and HN post. The learned-baseline anomaly-detection variant (statistical profiling, peer comparison) is explicitly on the roadmap for a later release and is labelled as such in `detections.py`. Calling the shipped detector "anomaly detection" is overclaim.
- **Do not conflate AIR-04 with ASI10.** AIR-04 detects gaps in our own chain (missing tool_end records, silent intervals). ASI10 Rogue Agents is about agents acting outside their authorization scope / stealth infiltration. OWASP lists signed audit logs as a *mitigation* for ASI10, not a detection signal. Calling AIR-04 "ASI10 coverage" is overclaim. Real ASI10 coverage requires a behavioral-scope detector.

### Layered architecture (the spine of the product as of 0.7.1)

The detectors above are Layer 0. Each subsequent layer is a separate `airsdk` subpackage with its own demo script, CLI surface, and crypto trust contract. Treat layers as independently dependable: a customer can adopt Layer 1 without Layer 2, Layer 3 without Layer 4, etc.

- **Layer 1, External Trust Anchor (`airsdk.anchoring/`).** RFC 3161 timestamps + Sigstore Rekor inclusion proofs over BLAKE3 chain roots. `RFC3161Client` (FreeTSA default; DigiCert / GlobalSign / Sectigo via `tsa_url`), `RekorClient` (raw ECDSA P-256 with Prehashed semantics; Ed25519 is in the schema but not exercised by `rekor.sigstore.dev`), `AnchoringOrchestrator` (default cadence: every 100 steps OR every 10 seconds). Three layers of recovery (background emit, atexit flush, on-disk catch-up via `hydrate_from_chain`) so no step is silently dropped across SIGKILL. CLI: `air anchor`, `air verify`, `air verify-public` (the last runs the five-step verification flow with zero Vindicara API calls). Demo: `packages/projectair/scripts/e2e_layer1.py`.
- **Layer 2, Causal Reasoning (`airsdk.causal/`).** `build_causal_graph(records)` returns a `CausalGraph` with hard edges (CHAIN_LINK / LLM_PAIR / TOOL_PAIR / LLM_DECISION / AGENT_MESSAGE at confidence 1.0) and soft edges (OUTPUT_REUSE at 0.5–1.0). `explain_step` and `explain_finding` produce depth-bounded `Explanation` objects (default `max_depth=4`). CLI: `air explain --step <ord-or-uuid>` and `air explain --finding <detector_id>`. The hard/soft distinction is the trust contract for analyst-facing reports.
- **Layer 3, Containment with Auth0 (`airsdk.containment/`).** `ContainmentPolicy` (deny_tools / deny_arg_patterns / block_on_findings / step_up_for_actions; deny rules override step-up). `Auth0Verifier` does real RS256/RS384/RS512 JWT verification via `PyJWKClient`; named for Auth0 because Auth0 is the documented integration target but the implementation is generic OIDC + JWKS. `StepKind.HUMAN_APPROVAL` carries the verified `Auth0Claims` (`sub`, `email`, `iss`, `aud`, `iat`, `exp`, `jti`) plus the original signed JWT; AgDR schema is **0.4**. `AIRRecorder.tool_start()` consults the policy and either allows, blocks, or step-ups (raising `BlockedActionError` or `StepUpRequiredError`); `AIRRecorder.approve(challenge_id, token)` validates the token, records `HUMAN_APPROVAL`, then re-emits the originally-halted tool_start as a fresh non-blocked record. Forged or wrong-issuer tokens leave the action permanently halted. CLI: `air approve` with `--token` / `--device` / `--authorize-url` modes. `Auth0Tenant`, `build_authorize_url`, `make_pkce_pair`, `start_device_flow`, `poll_device_token` are the wiring helpers. Demo: `scripts/e2e_layer3.py`.
- **Layer 4, AgDR Handoff Protocol Wave 1 (alpha) (`airsdk.handoff/`).** Cross-agent chain of custody: when Agent A delegates to Agent B, a Parent Trace ID (`PTID` = W3C trace_id verbatim, 32 lowercase hex) propagates through capability tokens and HTTP headers, a `HANDOFF` record at the source pairs cryptographically with a `HANDOFF_ACCEPTANCE` record at the target, and a Sigstore Rekor counter-attestation with hashed identifiers proves Agent B validated the capability token without leaking topology to the public log. New schemas: `agdr/v2.handoff`, `agdr/v2.handoff_acceptance`, `agdr/v2.validation_attestation` (independent of v0.4 record schema; legacy chain integrity unchanged). Modules: `canonicalize` (RFC 8785 JCS; rejects bytes / datetime / UUID / Decimal / Enum / pathlib / tuple inputs to prevent cross-language interop bugs being locked into a permanent Rekor anchor), `trace` (W3C Trace Context; `reconcile_channels` fails closed when JWT `air_ptid` / W3C `traceparent` / `Air-Parent-Trace-Id` disagree), `identity` (`IdentityFormat` enum: `sigstore_fulcio` / `x509_pem` / `local_dev`), `handoff_record`, `idp.{Auth0Adapter, AdapterRouter, OktaAdapter, EntraAdapter, SpiffeAdapter}` (Auth0 is the only live adapter in Wave 1; Okta / Entra / Spiffe ship in v1.5 alongside enterprise federation), `validation_proof` (Rekor counter-attestation with hashed identifiers), `verifier.CrossAgentVerifier` (eight-step verification, Section 8.2). CLI: `air handoff verify --ptid <ptid> --chain <path>`. Demo: `scripts/e2e_layer4.py` (use `--live-rekor` to submit to public Sigstore Rekor). Wave 1 was demonstrated live against Auth0 tenant `dev-kilt2vkudvbu75ny.us.auth0.com` on 2026-05-07; Rekor anchor at log index 1465403522. Three pre-spec design decisions are locked: (4) Rekor counter-attestation replaces self-attested validation, (5) PTID = W3C trace_id verbatim with `air_ptid` JWT claim, (6) cross-tenant in v1 via Sigstore Fulcio + OIDC Discovery (no pre-arranged trust); see `project_layer4_design_decisions.md` in memory.

The four layers correspond to the public framing: detection (what wrong looks like) + verification (was the chain real?) + explanation (why did it happen?) + containment (stop it + bind to a human) + cross-agent trust (the chain survives delegation).

### Terminology: "Intent Capsule" is the public-facing term

OWASP's ASI01 mitigation #5 names "intent capsule" as the emerging pattern for binding declared goal, constraints, and context to each execution cycle in a signed envelope. That is what AIR writes. Lead external comms (README, blog, pitch) with "Signed Intent Capsule." The record-level Python types (`AgDRRecord`, `AgDRPayload`, `packages/projectair/src/airsdk/agdr.py`) stay named AgDR for format compatibility with the accountability.ai/me2resh spec, but describe them as "AgDR-format-compatible Intent Capsules" in docs. This defuses the naming-collision risk around authorship claims on AgDR.

### Roadmap (next)

Layers 1, 2, 3, and 4 Wave 1 shipped between 2026-05-06 and 2026-05-07. Detector coverage is 10 of 10 Agentic + 3 LLM + 1 AIR-native. Next-release targets:
- Layer 4 Wave 2: cross-tenant federation via Sigstore Fulcio + OIDC Discovery (lifts the v1 single-tenant feature flag once Wave 1 has at least one reference deployment).
- Layer 4 v1.5: private / enterprise federation (custom CA roots, archived JWKS); live `OktaAdapter` / `EntraAdapter` / `SpiffeAdapter` (Wave 1 ships interface-only placeholders that raise `IdPNotImplementedError`).
- Layer 1 v0.4.1: anchoring key rotation with key transparency log; bundled TSA root certificate set; `docs/anchoring.md` + `docs/threat-model.md`.
- Learned-baseline ASI10 variant (statistical behavioural profile + peer comparison; requires training-data collection).
- Full ASI04 Agentic Supply Chain detector beyond MCP naming patterns (dependency poisoning, tool-manifest tampering).
- Framework integrations: CrewAI; AutoGen (Microsoft v0.4+ line and AG2 community fork are separate targets). A2A protocol capture is tracked separately as a new surface area, not an SDK wrapper.
- LangChain / OpenAI tool-call interceptor wrappers so containment kicks in automatically without manual `tool_start` calls (deferred from Layer 3; planned for v0.7 follow-up).
- AIR Cloud (hosted ingestion + dashboard backing the Team tier; NeMo Guardrails ingestion lands in Phase 1.5; see `project_nvidia_partnership_roadmap.md` in memory).

### Vindicara ops chain (dogfooded as of `vindicara` 0.3.0)

Vindicara runs Project AIR on its own production infrastructure. Every API request is recorded as a signed AgDR record using the same `airsdk` library customers use; chains anchor to public Sigstore Rekor; the published catalog is at `https://vindicara.io/ops-chain/`. Trust contract matches customer chains exactly: signed in-process at the moment of action by `airsdk.AIRRecorder`, anchored async by a separate cron Lambda, redaction at publish time only.

- `src/vindicara/ops/` (DDB transport, redaction policy, anchorer + publisher cron Lambdas, `OpsRecorder` helpers, `request_chain` context manager)
- `src/vindicara/api/middleware/ops_chain.py` (FastAPI middleware bracketing every request; outermost in stack so auth failures and rate-limit hits are also recorded; no-op when `VINDICARA_OPS_CHAIN_TABLE` env unset)
- `src/vindicara/infra/stacks/ops_chain_stack.py` (CDK: DDB + public S3 bucket + two cron Lambdas at 60s cadence)
- `docs/design/ops-chain.md` (architecture rationale, advisor-incorporated trust-model decision)
- `docs/ops-chain.md` (operator runbook + verify instructions)
- `scripts/e2e_ops_chain.py` (offline smoke test of the full pipeline)
- `site/src/routes/ops-chain/+page.svelte` (public verify page; fetches manifest live, shows latest Rekor log index)

Use "Project AIR" on hero pages, pitch decks, whitepapers, legal, press, investor materials. Use "AIR" in code, docs, CLI, and technical copy.

## Current state

- `projectair` **1.0.0** on PyPI (2026-05-18). **1.0.1 in-flight** (relaxed `cryptography` dep, conditional ML-DSA imports, `betterproto`).
- `vindicara` 0.2.0 live (server-side engine behind AIR Cloud).
- AgDR schema **v0.6**. "Signed Intent Capsule" is the public-facing term for AgDR records.
- Working venv: `.venv-air/` (Python 3.13).

## Claims discipline (enforced on every response)

- Detector count: **"10 OWASP Agentic + 3 OWASP LLM + 3 AIR-native = 16 total."** Never "14" or "8 of 10."
- ASI10 is **declared-scope Zero-Trust enforcement**, NOT anomaly detection. Learned-baseline variant is roadmap, not shipped.
- AIR-04 (chain-integrity gap) is NOT ASI10 coverage. Do not conflate.
- Every public claim must be grounded in an actual source document, not plausible-sounding generalization.
- HF0 pitch + Hacker News launch imminent. Diligence sensitivity is high.

## Repo map

- `packages/projectair/` -- public MIT package (`air` CLI + `airsdk` library). The product.
- `packages/projectair-pro/` -- commercial tier (`airsdk_pro`). SIEM, governance, premium detectors/reports. Not on PyPI.
- `packages/air-dashboard/` -- AIR Cloud dashboard (SvelteKit 2, Svelte 5, Tailwind 4, Three.js, Vitest).
- `vindicara-site/` -- the live product site and Flightdeck console (NOT a marketing site). Hosts the Flightdeck product console plus product, blog, legal, and compliance surfaces (`vindicara-site/src/lib/console/`, Auth0 PKCE, live `/v1/*` API). SvelteKit 2, Svelte 5, Tailwind 4. This is the directory the deploy workflow builds.
- `site/` -- LEGACY, not deployed. Superseded by `vindicara-site/`. Do not edit unless explicitly migrating it.
- `src/vindicara/` -- Apache-2.0 engine substrate.
- `tests/` -- pytest for `src/vindicara/`. Separate from `packages/projectair/tests/`.
- Pitch the split as **Snyk-style: MIT CLI + SDK top-of-funnel, commercial pro tier + engine behind the cloud**.
- When the user says "the dashboard," confirm which one (air-dashboard vs `vindicara-site` Flightdeck (`/dashboard`) vs legacy `src/vindicara/dashboard/`).

## Commands

```bash
# Install
pip install -e ".[api,dev]"
pip install -e "packages/projectair[dev]"

# Test (projectair)
pytest packages/projectair/tests
air demo

# Test (engine, 80% coverage floor)
./scripts/test.sh

# Lint + type check (src/vindicara + tests/ only)
./scripts/lint.sh

# Common pytest
pytest tests/unit/engine/test_policy.py
pytest -k "guard and not adversarial"
pytest -m adversarial

# FastAPI local
uvicorn vindicara.api.app:create_app --factory --reload

# CDK
./scripts/build-lambda.sh
VINDICARA_AWS_ACCOUNT_ID=... cdk synth
VINDICARA_AWS_ACCOUNT_ID=... cdk deploy VindicaraData VindicaraEvents VindicaraAPI

# Product site + Flightdeck console (vindicara-site is the deployed dir; site/ is legacy)
cd vindicara-site && npm install && npm run dev
cd vindicara-site && npm run check    # lint bar; failures block deploy
cd vindicara-site && npm run build    # prerender; fails if a linked /legal/*.docx is untracked

# AIR Cloud dashboard
cd packages/air-dashboard && npm install
cd packages/air-dashboard && npm run ci   # check + test + build + bundle:check

# Flightdeck console routes live under vindicara-site/ (see Product site commands); open /dashboard after `npm run dev`.

# Publish (always cd packages/projectair first)
rm -f dist/*.whl dist/*.tar.gz && python -m build && python -m twine check dist/* && python -m twine upload dist/projectair-<ver>*
```

Site deploy: auto on push to `main` when `vindicara-site/**` changes via `.github/workflows/deploy-site.yml`. Manual: `scripts/deploy-site.sh`.

CI: `ci-projectair.yml` (ruff + pytest, Python 3.12/3.13) gates the OSS package. `deploy-site.yml` auto-deploys the site.

E2E demos (after `pip install -e "packages/projectair[dev]"`):

```bash
python packages/projectair/scripts/e2e_layer1.py [--live-tsa --live-rekor]
python packages/projectair/scripts/e2e_layer3.py
python packages/projectair/scripts/e2e_layer4.py [--live-rekor]
```

## Repo Layout (actual, current)

`docs/SPEC.md` contains an aspirational project-structure diagram inherited from early planning. Ignore it when writing code. The ground truth is below.

### `packages/projectair/` (the public MIT package, this is the product)

- `packages/projectair/pyproject.toml` — own build. Declares `[project.scripts] air = "projectair.cli:main"`. Wheel packages are `src/airsdk` + `src/projectair`.
- `packages/projectair/src/airsdk/` — library surface:
  - `callback.py` (`AIRCallbackHandler` for LangChain; lives at the top of `airsdk/`, not under `integrations/`)
  - `recorder.py` (`AIRRecorder` writes signed records; consumes `containment=` + `auth0_verifier=` for Layer 3)
  - `transport.py` (transport sinks; `FileTransport` `os.fsync`s after every record so Layer 1's chain-as-spool recovery model is sound; opt out with `FileTransport(path, fsync=False)` for max throughput at the cost of weaker crash recovery)
  - `agdr.py` (BLAKE3 + Ed25519/ML-DSA-65 signing; the "AgDR format" layer, product-labelled "Signed Intent Capsule"; current AgDR `version` is **0.5** as of ML-DSA-65 addition)
  - `detections.py` (all ASI + AIR-XX detectors)
  - `registry.py` (`AgentRegistry`, `AgentDescriptor`, `BehavioralScope` pydantic schemas; YAML/JSON loader for the operator-supplied Zero-Trust declaration that ASI03 + ASI10 enforce against)
  - `article72.py` + `_article72_content.py` (Markdown report generator behind `air report article72`)
  - `exports.py` (JSON/PDF/CEF emitters)
  - `types.py` (`AgDRRecord`, `AgDRPayload`, `Finding`, `ForensicReport`, `StepKind`, `SigningAlgorithm` including `ANCHOR` from Layer 1 and `HUMAN_APPROVAL` from Layer 3)
  - `_concrete_demo.py` (the brutal narrative chain that `air demo` actually runs: poisoned README → SSH key exfiltration). `_demo.py` is the older sanity-only demo and is no longer the default.
- `packages/projectair/src/airsdk/anchoring/` — Layer 1. `rfc3161.py` (`RFC3161Client`, FreeTSA default), `rekor.py` (`RekorClient`, ECDSA P-256 Prehashed), `orchestrator.py` (`AnchoringOrchestrator`, `FailurePolicy`), `policy.py`, `identity.py` (`load_anchoring_key`; `AIRSDK_ANCHORING_KEY` env or `~/.config/projectair/anchoring_key.pem` mode 0600), `exceptions.py`.
- `packages/projectair/src/airsdk/causal/` — Layer 2. `inference.py` (`build_causal_graph`), `explain.py` (`explain_step`, `explain_finding`), `types.py` (`CausalGraph`, `Edge`, `Explanation`).
- `packages/projectair/src/airsdk/containment/` — Layer 3. `policy.py` (`ContainmentPolicy`), `auth0.py` (`Auth0Verifier`, `Auth0Claims`), `auth0_flows.py` (device flow, PKCE, authorize-URL helpers, polling), `exceptions.py` (`BlockedActionError`, `StepUpRequiredError`, `ApprovalInvalidError`, `Auth0DeviceFlowError`).
- `packages/projectair/src/airsdk/handoff/` — Layer 4 Wave 1 (alpha). `canonicalize.py` (RFC 8785 JCS, strict input policy), `trace.py` (W3C Trace Context, `generate_ptid`, `parse_traceparent`, `child_context`, `reconcile_channels`), `identity.py` (`IdentityFormat`, `AgentIdentity`, `generate_local_dev_identity`), `handoff_record.py` (`agdr/v2.handoff` + `agdr/v2.handoff_acceptance` builders), `idp/` (`IdPAdapter`, `AdapterRouter`, `Auth0Adapter` live; `OktaAdapter`/`EntraAdapter`/`SpiffeAdapter` raise `IdPNotImplementedError` until v1.5), `validation_proof.py` (Rekor counter-attestation with hashed identifiers), `verifier.py` (`CrossAgentVerifier` eight-step), `exceptions.py` (`ReplayAnomalyError`, `UnregisteredIssuerError`, `CustomClaimMissingError`, etc.).
- `packages/projectair/src/airsdk/integrations/` — `openai.py` (`instrument_openai`), `anthropic.py` (`instrument_anthropic`), `llamaindex.py` (`instrument_llamaindex`, transparent proxy over any `llama_index.core.llms.LLM` subclass), `gemini.py` (`instrument_gemini` over `google-genai`, with streaming helpers in `_gemini_streams.py`), `adk.py` (`instrument_adk` over `google-adk`).
- `packages/projectair/src/projectair/cli.py` — Typer CLI. All `air` subcommands live here: `demo`, `trace`, `report`, `anchor`, `verify`, `verify-public` (Layer 1); `explain` (Layer 2); `approve` (Layer 3); `handoff` (Layer 4); `upgrade`.
- `packages/projectair/tests/` — pytest suite for the MIT package. Separate from the root `tests/`. Subdirs include `tests/anchoring/`, `tests/causal/`, `tests/containment/`, `tests/handoff/` (56 Layer 4 tests). Run with `pytest packages/projectair/tests`.
- `packages/projectair/scripts/` — `e2e_layer1.py`, `e2e_layer3.py`, `e2e_layer4.py`, `bench_fsync.py` (the source of the ~5% APFS overhead claim).
- `packages/projectair/examples/` — `build_sample_trace.py` and `sample_trace.log` for manual testing of `air trace`; `gemini_demo.py`, `adk_demo.py`, `nim_demo.py`.

### `src/vindicara/` (Apache-2.0 engine substrate)

- `src/vindicara/sdk/` — public SDK surface (`client.py`, `decorators.py`, `types.py`, `exceptions.py`). `vindicara.__init__` re-exports `Client` and the typed exceptions. The package ships a `py.typed` marker, so downstream `mypy --strict` users get Vindicara's type hints directly.
- `src/vindicara/engine/` — policy engine (`evaluator.py`, `policy.py`, `rules/`). `Evaluator.with_builtins()` is the canonical bootstrap; `PolicyRegistry` holds built-in policies. There is no `cache.py` or `composite.py` yet.
- `src/vindicara/mcp/` — MCP scanner. Uses `scanner.py` + `findings.py` + `prober.py` + `transport.py`. Modules are named `findings`/`prober`, not `inspector`/`bom`/`risk`.
- `src/vindicara/identity/` — agent IAM (`registry.py`, `authz.py`, `models.py`). No `credentials.py` yet.
- `src/vindicara/monitor/` — drift detection (`baseline.py`, `drift.py`, `breaker.py`, `models.py`).
- `src/vindicara/compliance/` — compliance engine. Uses `collector.py` + `reporter.py` + `frameworks.py` + `models.py` (not one file per framework). Frameworks are data-driven.
- `src/vindicara/api/` — FastAPI app. `app.py::create_app()` is the application factory. Routes: `guard`, `policies`, `scans`, `agents`, `reports`, `monitor`, `health`. Middleware: `auth` (API key), `rate_limit`, `request_id`, `security_headers`. A dashboard ASGI sub-app is mounted at `/dashboard`.
- `src/vindicara/dashboard/` — SSR-ish dashboard with its own auth stack (`dashboard/auth/`: passwords, MFA/TOTP, JWT tokens, signup/login middleware), templates, and API key management. Lives behind `/dashboard`.
- `src/vindicara/audit/` — audit logger + storage (DynamoDB/S3).
- `src/vindicara/config/settings.py` — `VindicaraSettings` via pydantic-settings, `VINDICARA_` env prefix. Constants live alongside their module (e.g. `config.constants` is referenced by `engine/evaluator.py`).
- `src/vindicara/infra/` — CDK app. `infra/app.py` is the CDK entry point (wired via `cdk.json`). Stacks: `DataStack` (DynamoDB tables + S3 audit bucket), `EventsStack` (EventBridge bus), `APIStack` (Lambda + API Gateway, wired to the other stacks' outputs). No separate `monitoring_stack.py`.
- `src/vindicara/lambda_handler.py` — Mangum entry point (`handler = Mangum(create_app(), lifespan="off")`). This is what API Gateway calls in production.
- `site/` — SvelteKit 2 + Svelte 5 + Tailwind 4 marketing site and blog (static adapter). Separate from both `src/vindicara/dashboard/` (legacy SSR dashboard mounted under `/dashboard`) and `packages/air-dashboard/` (the dedicated AIR Cloud dashboard).
- `packages/air-dashboard/` — SvelteKit 2 + Svelte 5 + Tailwind 4 + Three.js, static adapter, Vitest. The dashboard customers will see (separate from `site/` and from the legacy `src/vindicara/dashboard/`). Has its own `npm run ci` (check + test + build + bundle:check) and a bundle-size budget enforced by `scripts/check-bundle.mjs`.
- `tests/` — pytest. Mirrors `src/` for units (`tests/unit/{engine,mcp,identity,monitor,compliance,sdk,dashboard}`). Integration tests live under `tests/integration/{api,mcp,dashboard}` and hit the real ASGI app via `httpx.AsyncClient` + `ASGITransport` (see `tests/conftest.py`). `TEST_API_KEY = "vnd_test"` is the shared dev key; the `app` fixture registers it via `create_app(dev_api_keys=[...])`.

There is no `tests/e2e/` directory, no `scripts/deploy.sh`, and no `src/vindicara/engine/cache.py`.

## Architecture Notes That Require Reading Multiple Files

- **Policy evaluation flow.** `sdk.Client.guard()` → `engine.Evaluator.evaluate_guard()` → for each of input/output calls `Evaluator.evaluate()` → `PolicyRegistry.get(policy_id).evaluate(text)` → `Policy.evaluate()` runs every `Rule` and folds the rule results into a single `GuardResult` (`blocked` if any rule triggers `CRITICAL`/`HIGH`, else `flagged` if any triggered, else `allowed`). Max input/output lengths come from `config.constants.MAX_INPUT_LENGTH`/`MAX_OUTPUT_LENGTH`. When both input and output are supplied, the worst verdict wins (blocked > flagged > allowed).
- **API middleware stack order matters.** `create_app()` adds middleware in this order: `SecurityHeaders` → `RequestID` → `APIKeyAuth` → `RateLimit` → CORS → dashboard auth. Starlette applies middleware in reverse of add order, so requests traverse CORS first and security headers last. When adding middleware, preserve this order or auth/rate-limit bypass becomes possible.
- **API key store.** `APIKeyStore` lives on `app.state.key_store`. Tests register keys by passing `dev_api_keys=[...]` to `create_app()`; production keys are issued/persisted via the dashboard (`dashboard/keys/`) and the `api_keys_table` DynamoDB table from `DataStack`.
- **Dashboard is mounted, not merged.** `create_app()` imports and mounts `create_dashboard_app()` at `/dashboard`. The `DashboardAuthMiddleware` is added to the parent app (not the sub-app), so dashboard auth runs for every parent-app request. Reordering this also touches the public API.
- **Compliance is data-driven.** Frameworks (EU AI Act Article 72, NIST AI RMF, SOC 2 AI) are defined as data in `compliance/frameworks.py` and consumed by `compliance/collector.py` (`EvidenceCollector`) + `compliance/reporter.py` (`ComplianceReporter`). Do not add a new per-framework module; register a new framework definition instead.
- **SDK namespaces.** `Client` composes sub-namespaces (`MCPNamespace`, `AgentsNamespace`, monitor, compliance), each wrapping a single engine/registry/reporter. Adding a new SDK surface means: build the engine in `src/vindicara/<module>/`, then wire a namespace class inside `sdk/client.py` and expose it as a property on `Client`. Re-export anything public from `vindicara/__init__.py`.
- **Lambda vs local.** `lambda_handler.py` and local `uvicorn` both call `create_app()`, so behavior should be identical. DynamoDB/S3 access in Lambda runs under the IAM role from `APIStack`; locally it falls back to whatever `boto3` picks up from the environment. `VINDICARA_OFFLINE_MODE=true` disables cloud calls entirely for local/SDK use.
- **CDK wiring.** `infra/app.py` instantiates `DataStack` and `EventsStack` first, then passes their outputs into `APIStack` as constructor args. Stacks are NOT auto-discovered; adding a stack means editing `infra/app.py` to instantiate it.
- **Chain signing: Ed25519 (default) or ML-DSA-65 (FIPS 204, experimental opt-in).** `Signer` auto-detects the algorithm from the key type. `AgDRRecord.signature_algorithm` field (v0.5) tells `verify_record` which verifier to dispatch to. Ed25519 signatures are 64 bytes; ML-DSA-65 signatures are 3,309 bytes (~7 KB hex per record). Both use 32-byte seeds. Mixed-algorithm chains (some records Ed25519, some ML-DSA-65) verify correctly.
- **Layer 1 anchoring crypto: ECDSA Prehashed, not Ed25519 or ML-DSA.** `RekorClient` signs with raw ECDSA P-256 over the **already-hashed** 32-byte SHA-256 chain root using `cryptography`'s `Prehashed` mode (no further hashing at sign time). Ed25519 is in the rekor-types schema but `rekor.sigstore.dev` does not actually exercise Ed25519 hashedrekord verification in production. ML-DSA is not supported by Rekor. Do not "fix" the code to use Ed25519 or ML-DSA for anchoring; both break Rekor inclusion-proof verification empirically. The two-key model (chain signer = Ed25519 or ML-DSA; anchoring identity = ECDSA P-256) is correct.
- **Layer 1 chain-as-spool recovery.** `AnchoringOrchestrator` does not buffer pending anchor requests in memory; the chain on disk *is* the spool. `FileTransport.emit` `os.fsync`s after every record (~5% APFS overhead per `bench_fsync.py`); on startup, `hydrate_from_chain` reads the on-disk chain and re-emits any pending anchors. macOS `os.fsync` does not force the platter write (`F_FULLFSYNC` does, not yet wired); on macOS the durability guarantee is weaker than Linux until that lands. Linux ext4/xfs durability is strong but on rotational disks expect noticeably higher overhead than the macOS APFS measurement; high-throughput Linux deployments should benchmark.
- **Layer 3 fail-closed semantics.** Forged or wrong-issuer Auth0 tokens leave the originally-halted action permanently halted. An attacker submitting a bad token to `AIRRecorder.approve()` cannot drive the agent forward. Deny rules in `ContainmentPolicy` always override step-up rules — "absolutely never" stays absolute even when an operator forgets to remove a step-up rule for the same tool.
- **Layer 4 fail-closed semantics.** `reconcile_channels` hard-fails when JWT `air_ptid`, W3C `traceparent`, and `Air-Parent-Trace-Id` channels disagree on the trace-id; `AdapterRouter` rejects unregistered issuers (`UnregisteredIssuerError`) rather than silently falling back to OIDC discovery against an unknown issuer; `verifier` step 7 uses two-bound temporal ordering math (Section 15.15) — naive `>` comparison is explicitly forbidden because it cannot distinguish "receiver clock lagging sender" from "acceptance arrived after timeout"; `validation_proof` hashes every human-readable identifier (agent ID, JTI, issuer URL, PTID) so the public Rekor log carries zero workflow topology metadata.
- **`canonicalize` strict input policy is intentional.** `airsdk.handoff.canonicalize` rejects bytes / datetime / UUID / Decimal / Enum / pathlib / tuple inputs with a JSONPath-style diagnostic. Reason: a permissive canonicalizer would let callers pass values that one language serializes one way and another language serializes differently, which would lock a cross-language interoperability bug into a permanent Sigstore Rekor anchor. Do not relax this without coordinating across all IdP adapter implementations. The three canonical empty-payload conventions (`BLAKE3(b"")`, `BLAKE3(b"{}")`, `BLAKE3(b"[]")`) are distinct and not interchangeable.

## Quality gates (apply to every roadmap item)

Every shipped feature, OSS or Cloud, must address all four:
1. **End-to-End Proof** — runnable demo a customer can execute in under 60 seconds (`air demo` is the exemplar).
2. **Test Coverage Proof** — measured numbers in release notes, coverage badge or report committed; 80% floor enforced by `./scripts/test.sh`.
3. **Deployment / Readiness Boundary** — explicit `experimental` / `beta` / `production` label on docs, pricing page, and CLI surface. Pricing-page features must be at minimum `beta`. `production` requires SLO + monitoring + runbook.
4. **Customer-Facing Value** — one-sentence customer-language description before engineering starts. If you can't write it, the feature isn't ready to scope.

See `feedback_four_quality_gates.md` in memory for the full discipline.

## Hard rules specific to this repo

- Never use em dashes in any output. Use commas, semicolons, colons, or separate sentences.
- Never mention Emirates Airlines.
- No `Any` types, no bare `except`, no `print` in production paths. `mypy --strict` is the bar.
- No dynamic code evaluation (`eval`, `exec`, `pickle`, unsafe YAML) on untrusted input.
- 300 lines max per file. If you need "and" to describe a function, split it.
- Root cause fixes only. No band-aids, no "temporary" patches.

## Quality gates (every roadmap item)

1. **End-to-End Proof** -- runnable demo under 60 seconds.
2. **Test Coverage Proof** -- 80% floor enforced by `./scripts/test.sh`.
3. **Deployment / Readiness Boundary** -- `experimental` / `beta` / `production` label.
4. **Customer-Facing Value** -- one-sentence customer-language description before engineering starts.

## Context

**AWS account migration in flight.** SLTR `335741630084` (us-east-1) to Vindicara C-Corp `399827112476` (us-west-2). Three hardcoded locations: `data_stack.py`, `deploy-site.sh`, GitHub Actions workflow. See `MIGRATION_PLAN.md` and `project_aws_migration.md` in memory.

## Detailed docs (read when working in the relevant area)

- `docs/DETECTORS.md` -- full detector taxonomy (ASI01-10, AIR-01..06, NemoGuard, framing discipline, AIR-04 vs ASI10). Read before editing detectors or public copy.
- `docs/ARCHITECTURE.md` -- layered spine (Layers 0-5), crypto trust contracts, PyPI release details, framework integrations, ops chain, detailed code location, architecture cross-cutting notes, roadmap. Read before adding layers, integrations, or navigating unfamiliar modules.
- `docs/STANDARDS.md` -- engineering standards, SDK design, FastAPI patterns, testing, security architecture, performance targets, AWS infra, quality gates.
- `docs/SPEC.md` -- product vision, competitive landscape, pricing, GTM, fundraise context. Read for product decisions or external content.

Memory: `/Users/KMiI/.claude/projects/-Users-KMiI-Desktop-vindicara/memory/MEMORY.md`.
