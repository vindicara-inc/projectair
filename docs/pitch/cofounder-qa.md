# Vindicara / Project AIR: Co-Founder Q&A Brief

This document is structured as investor-style questions and answers so a co-founder can walk into any pitch, diligence call, or partner meeting and answer confidently. Every answer is grounded in shipped code, public artifacts, or verified facts. Nothing is fabricated.

Last updated: 2026-05-13.

---

## 1. THE COMPANY

**Q: What is Vindicara?**

Vindicara is an AI security company. We build the forensic governance layer for autonomous AI agents. Our flagship product is Project AIR (AI Incident Response), an open-source SDK and CLI that records every decision an AI agent makes as a cryptographically signed evidence chain, detects when the agent goes off-script, explains why it happened, and can stop it in real time.

**Q: What is the legal entity?**

Vindicara, Inc. Delaware corporation. Principal office at 696 S New Hampshire Ave, Los Angeles, CA 90005.

**Q: Who is the founder?**

Kevin Minn. Cybersecurity student. Previously ran SLTR Digital LLC, where he shipped 6 AI products over 12+ months, including Luminetic (an AI-powered iOS App Store compliance scanner that predicts Apple rejection reasons before submission). Full-time on Vindicara since March 2026. Previously applied to Y Combinator with 1099Pass (AI-powered loan readiness for self-employed borrowers).

**Q: When did the company start?**

Kevin went full-time in March 2026. The Project AIR pivot (from the original five-pillar runtime security platform positioning) happened in April 2026. The first public release hit PyPI on April 22, 2026.

**Q: What stage is the company?**

Pre-seed. Pre-revenue. The open-source product is live and installable. The commercial tiers (AIR Cloud, Enterprise) are not yet live.

**Q: What is the fundraise plan?**

$500K SAFE at $5M post-money cap. Use of funds: 12 months of solo-founder runway, AWS infrastructure, first contract hire (developer advocate or community), and a security audit of the SDK before the enterprise push.

---

## 2. THE PROBLEM

**Q: What problem does Vindicara solve?**

When an AI agent breaks something in production, there is no way to prove what happened. No forensic record. No chain of custody. No evidence that survives an audit, a lawsuit, or a regulator. Prevention tools (prompt injection filters, guardrails) try to stop bad things from happening. Nobody owns what happens after the bad thing occurs. Vindicara owns that.

**Q: Why is this a problem now?**

Four converging forces:

1. The EU AI Act enforcement deadline is August 2, 2026. High-risk AI systems require runtime monitoring, audit trails, incident reporting, and conformity documentation. Non-compliance fines: up to 7% of global annual revenue.
2. Autonomous AI agents are exploding. Every major platform (Microsoft, Google, Anthropic, OpenAI, Salesforce) is shipping agents that execute multi-step workflows, access enterprise systems, modify databases, and trigger transactions at machine speed.
3. MCP (Model Context Protocol) is the new attack surface. Only 8% of MCP servers support OAuth, and nearly half of those have material implementation flaws (RSA Conference 2026 data).
4. The independent AI security market has a vacuum. CalypsoAI was acquired by F5 (now government-focused). Lakera was acquired by Check Point (enterprise-only). The developer-first, independent tier is empty.

**Q: Who are the buyers?**

Security teams and platform engineering teams deploying AI agents in production. The sharpest pain is in regulated industries: fintech, healthtech, govtech, insurance. These are the buyers who cannot afford to have an agent incident with no evidence trail.

**Q: What is the regulatory forcing function?**

EU AI Act Article 72 requires "post-market monitoring" for high-risk AI systems. That means: runtime logging, incident detection, reporting within required timeframes, and technical documentation. Project AIR generates all of that automatically from the signed evidence chain.

California SB 53 adds US-side pressure. NIST AI RMF and SOC 2 AI controls are the frameworks enterprise security teams already map to.

---

## 3. THE PRODUCT

**Q: What is Project AIR exactly?**

Project AIR is an open-source Python SDK and CLI (`pip install projectair`). It instruments AI agent code so that every decision the agent makes is recorded as a Signed Intent Capsule: a cryptographically signed envelope containing the declared goal, constraints, and context of each execution step. The term "Intent Capsule" comes directly from OWASP Top 10 for Agentic Applications v12.6, ASI01 mitigation #5.

Each capsule carries a BLAKE3 content hash and an Ed25519 digital signature, chained to the previous step. The result is a tamper-evident forensic chain that any third party can independently verify.

**Q: What does "Signed Intent Capsule" mean?**

It is the OWASP-recommended pattern for binding an agent's declared goal, constraints, and context to each execution cycle in a signed envelope. We implement it. The on-disk format is compatible with the AgDR (Accountable GenAI Data Record) specification from accountability.ai. We describe them publicly as "AgDR-format-compatible Intent Capsules."

**Q: What can you do with it?**

Four things, corresponding to the four layers of the product:

1. **Detect.** 16 detectors scan the capsule chain for known attack patterns, policy violations, and anomalies. 10 cover the full OWASP Top 10 for Agentic Applications. 3 cover OWASP LLM Top 10 categories. 3 are AIR-native (chain integrity, NemoGuard safety classification, NemoGuard corroboration).
2. **Verify.** The chain root is anchored to two independent public proofs: an RFC 3161 trusted timestamp (FreeTSA, DigiCert, GlobalSign, Sectigo) and a Sigstore Rekor transparency-log entry. Anyone can verify the chain using only public infrastructure. No Vindicara API call required.
3. **Explain.** Causal reasoning walks the chain and surfaces the 5-7 load-bearing records that caused a finding, with edges marked as hard (derived from explicit fields) or soft (inferred by content match).
4. **Contain.** High-stakes agent actions can be halted in real time, requiring Auth0-verified human approval before the agent continues. The chain records who authorized what, making it both an audit trail and a consent record.

**Q: What is the four-layer architecture?**

| Layer | Name | What it does | Version shipped |
|---|---|---|---|
| 0 | Detection | 16 detectors across OWASP Agentic, LLM, and AIR-native categories | 0.1.x through 0.9.0 |
| 1 | External Trust Anchor | RFC 3161 timestamps + Sigstore Rekor transparency log over BLAKE3 chain roots | 0.4.0 |
| 2 | Causal Reasoning | Infers step-to-step dependencies, produces narrowed evidence excerpts | 0.5.0 |
| 3 | Containment | Halt agent actions, require Auth0-verified human approval, record consent on-chain | 0.6.0 / 0.6.1 |
| 4 | AgDR Handoff Protocol | Cross-agent chain of custody with W3C Trace Context and Rekor counter-attestation | 0.7.0 (Wave 1 alpha) |

Layers are independently adoptable. A customer can use Layer 1 without Layer 2, Layer 3 without Layer 4.

**Q: What frameworks does AIR integrate with?**

Eight shipped integrations:

- LangChain (`AIRCallbackHandler`)
- OpenAI SDK (`instrument_openai`), including any OpenAI-compatible endpoint (NVIDIA NIM, vLLM, TGI, Together AI, Groq, Mistral, Fireworks)
- Anthropic SDK (`instrument_anthropic`)
- LlamaIndex (`instrument_llamaindex`)
- Google Gemini SDK (`instrument_gemini`)
- Google ADK (`instrument_adk`)
- NVIDIA NeMo Guardrails (`instrument_nemo_guardrails`)
- NVIDIA NemoGuard NIM classifiers (`NemoGuardClient`)

Planned: CrewAI, Microsoft AutoGen v0.4+, AG2 community fork. A2A protocol capture is tracked as a separate surface, not an SDK wrapper.

**Q: What is the demo experience?**

```bash
pip install projectair
air demo
```

That generates a fresh signed capsule chain using the SSH-exfiltration attack narrative (a poisoned README tricks an agent into reading the user's SSH key and exfiltrating it to an attacker URL). It verifies every signature, runs all 16 detectors, and writes a forensic report. Full cold-start in one command, under 10 seconds, no agent wiring required.

**Q: What export formats does AIR support?**

JSON, PDF, SIEM-compatible CEF (ArcSight Common Event Format), and Markdown compliance report templates (EU AI Act Article 72, NIST AI RMF, SOC 2 AI). Date-range filtering is supported on all report types.

---

## 4. DETECTOR COVERAGE (OWASP ALIGNMENT)

**Q: How many detectors does AIR have?**

16 total. 10 OWASP Agentic + 3 OWASP LLM + 3 AIR-native.

**Q: What are the 10 OWASP Agentic detectors?**

| ID | Name | What it detects |
|---|---|---|
| ASI01 | Agent Goal Hijack | Prompt injection, goal drift |
| ASI02 | Tool Misuse & Exploitation | Dangerous tool calls, argument patterns |
| ASI03 | Identity & Privilege Abuse | Identity forgery, unknown agents, out-of-scope tools, privilege escalation (Zero-Trust enforcement via AgentRegistry) |
| ASI04 | Agentic Supply Chain | MCP naming patterns (partial; full dependency-poisoning coverage on roadmap) |
| ASI05 | Unexpected Code Execution | eval, exec, shell invocation patterns |
| ASI06 | Memory & Context Poisoning | Retrieval-output and memory-write injection scans |
| ASI07 | Insecure Inter-Agent Communication | Identity, nonce, replay, downgrade, descriptor-forgery checks |
| ASI08 | Cascading Failures | Oscillating-pair cycles and fan-out bursts |
| ASI09 | Human-Agent Trust Exploitation | Fabricated-rationale and manipulation-language scans |
| ASI10 | Rogue Agents | Zero-Trust behavioral-scope enforcement via declared BehavioralScope (unexpected tools, fan-out breach, off-hours activity, session tool budget) |

Important framing: ASI10 is Zero-Trust behavioral-scope enforcement, not anomaly detection. The learned-baseline variant (statistical profiling, peer comparison) is on the roadmap, not shipped.

**Q: What are the 3 OWASP LLM detectors?**

| ID | Maps to | What it detects |
|---|---|---|
| AIR-01 | LLM01 Prompt Injection | Injection patterns in agent inputs |
| AIR-02 | LLM06 Sensitive Data Exposure | PII, credentials, secrets in outputs |
| AIR-03 | LLM04 Model DoS | Resource exhaustion patterns |

**Q: What are the 3 AIR-native detectors?**

| ID | Name | What it detects |
|---|---|---|
| AIR-04 | Untraceable Action | Gaps in the forensic chain (no OWASP equivalent) |
| AIR-05 | NemoGuard Safety Classification | Standalone findings when NVIDIA NemoGuard NIM classifiers flag unsafe content |
| AIR-06 | NemoGuard Corroboration | Cross-corroboration between AIR heuristic detectors and NemoGuard NIM classifiers |

**Q: Is ASI04 fully implemented?**

No. ASI04 covers MCP naming patterns only. Full dependency-poisoning and tool-manifest tampering detection is on the roadmap.

---

## 5. CRYPTOGRAPHY AND TRUST MODEL

**Q: What cryptographic primitives does AIR use?**

Two separate signing systems:

1. **Chain signing (per-record):** Ed25519 by default. Opt-in experimental ML-DSA-65 (FIPS 204 post-quantum signatures, requires `cryptography>=48.0.0`). Content hashes use BLAKE3. Step IDs are UUIDv7. Mixed-algorithm chains (some records Ed25519, some ML-DSA-65) verify correctly.
2. **Anchoring (Layer 1, Rekor):** ECDSA P-256 with Prehashed semantics. This is a separate key from the chain signer. Rekor does not exercise Ed25519 hashedrekord verification in production, so ECDSA P-256 is the correct path. Do not "fix" this; it was empirically verified against live Sigstore infrastructure.

This two-key model is intentional: chain signer = Ed25519 or ML-DSA; anchoring identity = ECDSA P-256.

**Q: What is ML-DSA-65?**

ML-DSA-65 is the NIST FIPS 204 post-quantum digital signature standard. It is resistant to quantum computing attacks. AIR ships it as opt-in experimental. Ed25519 remains the default. Mark as experimental in all docs until at least one customer uses it. ML-DSA-65 signatures are 3,309 bytes (~7 KB hex per record) compared to Ed25519's 64 bytes.

**Q: How does chain verification work without trusting Vindicara?**

The `air verify-public` command runs a five-step verification flow using only public infrastructure:

1. Verify every record's Ed25519/ML-DSA signature against the embedded public key.
2. Verify every record's BLAKE3 content hash.
3. Verify the hash chain (each record's prev_hash matches the previous record's content hash).
4. Verify the RFC 3161 timestamp token against the TSA's public certificate.
5. Verify the Sigstore Rekor inclusion proof against the Rekor transparency log.

Zero Vindicara API calls. The verifier only talks to FreeTSA and rekor.sigstore.dev, both of which are independent public infrastructure.

**Q: Is there a live proof?**

Yes. A reference chain was anchored to public Sigstore Rekor on 2026-05-07 at log index 1455601514. Anyone can look it up at https://search.sigstore.dev/?logIndex=1455601514. Layer 4's live proof is at Rekor log index 1465403522, demonstrated against a real Auth0 tenant.

**Q: What does "Admissible by Design" mean?**

The cryptographic chain maps to US Federal Rules of Evidence (FRE 901 authentication, FRE 902(13) certified records, FRE 803(6) business records exception), EU eIDAS Articles 25 and 26, and EU AI Act Article 72. The architecture is designed so the evidence chain can survive legal proceedings. There is a full whitepaper at vindicara.io/admissibility with an interactive chain explorer and a sample FRE 902(13) certification template.

We say "Admissible by Design" as an architecture claim, not a legal guarantee. The framing is honest: we built it to meet the evidentiary standards, but whether a specific court admits specific evidence is a legal question, not a technical one.

---

## 6. LAYER 3: CONTAINMENT AND HUMAN-IN-THE-LOOP

**Q: How does containment work?**

An operator defines a `ContainmentPolicy` with four rule types:

- `deny_tools`: block specific tools by name (absolute deny, no override)
- `deny_arg_patterns`: block by argument regex
- `block_on_findings`: halt when a detector fires
- `step_up_for_actions`: require human approval for matched actions

Deny rules always override step-up rules. "Absolutely never" stays absolute.

When `AIRRecorder.tool_start()` encounters a step-up rule, it raises `StepUpRequiredError` with a challenge ID. The agent halts. A human authenticates via Auth0 (browser flow, device flow, or direct token), and the signed JWT is submitted back. The recorder validates the token (RS256/RS384/RS512 via JWKS), records a `HUMAN_APPROVAL` step with the verified claims (sub, email, iss, aud, iat, exp, jti), and re-emits the originally halted action.

**Q: What happens if an attacker submits a forged token?**

The action stays permanently halted. Forged or wrong-issuer tokens leave the originally halted action in its blocked state. An attacker submitting a bad token cannot drive the agent forward. This is the fail-closed design.

**Q: Why Auth0 specifically?**

Two reasons. Technically, Auth0 is the right primitive for human-in-the-loop identity verification with standard OIDC/JWKS. Strategically, Kevin has Auth0 accounts and access to Auth0's startup program. The marketing exposure from that program (marketplace listing, startup ecosystem visibility) is part of the positioning. The verifier itself is generic OIDC + JWKS and works with any compliant IdP (Okta, Azure AD, Google Workspace), but Auth0 is the named integration target in docs and marketing.

---

## 7. LAYER 4: CROSS-AGENT TRUST (HANDOFF PROTOCOL)

**Q: What is Layer 4?**

When Agent A delegates work to Agent B, the cryptographic chain of custody must survive the handoff. Layer 4 is the AgDR Handoff Protocol. It propagates a Parent Trace ID (W3C trace_id, 32 hex chars) through capability tokens and HTTP headers. A HANDOFF record at the source pairs cryptographically with a HANDOFF_ACCEPTANCE record at the target. A Sigstore Rekor counter-attestation with hashed identifiers proves that Agent B validated the capability token without leaking any workflow topology to the public log.

**Q: What is the current status?**

Wave 1 alpha, shipped in 0.7.0. Single-tenant + synchronous Rekor mode + full eight-step verifier. Wave 2 lifts the cross-tenant feature flag once Wave 1 has at least one reference deployment. v1.5 ships private/enterprise federation (custom CA roots, archived JWKS, live Okta/Entra/Spiffe adapters).

**Q: What are the locked design decisions?**

Three pre-spec decisions are locked:

1. Rekor counter-attestation replaces self-attested validation (prevents agents from lying about whether they verified).
2. PTID = W3C trace_id verbatim (32 lowercase hex chars, carried in `air_ptid` JWT claim).
3. Cross-tenant in v1 via Sigstore Fulcio + OIDC Discovery (no pre-arranged trust required between tenant organizations).

**Q: What IdP adapters exist?**

Auth0Adapter is live. OktaAdapter, EntraAdapter, and SpiffeAdapter are interface-only placeholders that raise `IdPNotImplementedError`. They ship live in v1.5 alongside enterprise federation.

**Q: How does the verifier work?**

Eight steps:

1. PTID consistency check
2. Root identification
3. Handoff/acceptance pairing with replay-anomaly hard-fail
4. Pairing integrity
5. Capability token routing via AdapterRouter + Rekor proof verification
6. Intra-chain integrity
7. Two-bound temporal ordering (naive > comparison is forbidden; uses Section 15.15 math to distinguish clock lag from timeout)
8. Identity certificate validation

---

## 8. NVIDIA PARTNERSHIP

**Q: What is Vindicara's relationship with NVIDIA?**

Vindicara is a member of the NVIDIA Inception program (joined April 2026). The four-tier integration roadmap:

| Tier | Timeline | What |
|---|---|---|
| 1 | 0-3 months | NeMo Guardrails telemetry ingestion (shipped in 0.9.0) |
| 2 | 3-6 months | NemoGuard NIM classification corroboration (shipped in 0.9.0) |
| 3 | 6-12 months | Air-gapped NIM-packaged deployment for regulated enterprises |
| 4 | 12+ months | GPU-accelerated forensic search across massive trace corpora |

Tiers 1 and 2 shipped ahead of schedule in 0.9.0. Tier 3 depends on AIR Cloud baseline GA. Tier 4 requires customers ingesting at volume.

**Q: What shipped in the NVIDIA integration (0.9.0)?**

- `instrument_nemo_guardrails`: wraps NeMo Guardrails' `LLMRails` to capture every activated rail and every LLM call as signed capsule records.
- `NemoGuardClient`: wraps all three NVIDIA NemoGuard NIM classifiers (JailbreakDetect, ContentSafety, TopicControl) with signed tool_start/tool_end pairs per classification.
- AIR-05 (standalone NemoGuard safety findings) and AIR-06 (cross-corroboration between AIR heuristic detectors and NemoGuard classifiers).

**Q: Can I use NVIDIA NIM endpoints with AIR?**

Yes. Any OpenAI-compatible endpoint works via `instrument_openai`, including NVIDIA NIM, NemoClaw/OpenShell, vLLM, TGI, Together AI, Groq, Mistral, and Fireworks. No NIM-specific integration module is needed for inference. The NemoGuard-specific module is only for the safety classification NIMs.

**Q: What are the NVIDIA Inception branding rules?**

- Capital "P" in titles: "NVIDIA Inception Program"
- Lowercase "p" in sentences: "NVIDIA Inception program"
- Badge must be smaller than the Vindicara logo
- Scope by Kevin's decision: website only. Do not mention in blog posts, pitch decks, social posts, or press releases unless explicitly opted in for that surface.

---

## 9. BUSINESS MODEL AND PRICING

**Q: What is the pricing model?**

Four tiers:

| Tier | Price | What you get |
|---|---|---|
| **Open Source** | Free, MIT, forever | `air` CLI + `airsdk` Python SDK. 16 detectors. All 4 layers. LangChain/OpenAI/Anthropic/LlamaIndex/Gemini/ADK/NeMo/NemoGuard instrumentation. Signed Intent Capsule chain. JSON/PDF/CEF export. Compliance report templates. |
| **Individual** | $39/mo | AIR Cloud client SDK, premium compliance reports (NIST AI RMF, SOC 2 AI), premium detectors, license-gated via `projectair-pro`. |
| **Team** | $599/mo | Hosted AIR Cloud workspace, multi-agent dashboards, SIEM export (Datadog, Splunk, Sumo, Sentinel), incident workflows and alerting (Slack, email, PagerDuty, webhook). |
| **Enterprise** | Custom ($50K-$250K ACV) | SSO/SAML/RBAC, branded regulator-ready PDF evidence, multi-system compliance aggregation, insurance carrier integrations, on-prem/VPC/air-gapped deployment, dedicated IR contact, SLA, BAA. |

**Q: What is live today vs. what is planned?**

- **Live:** Open Source tier on PyPI (`pip install projectair`, version 0.9.0).
- **Not live:** Individual, Team, and Enterprise tiers. AIR Cloud is in development. The pricing page on vindicara.io shows all tiers but the paid tiers are not yet purchasable.

**Q: What is the go-to-market motion?**

Snyk-style open-source land-and-expand. MIT CLI + SDK is the top-of-funnel. Developers install it, embed it in agent code, produce signed forensic records. When the team needs a managed incident-response surface (dashboard, SIEM export, alerting), they upgrade to Team. When regulated enterprises need branded compliance evidence and on-prem deployment, they upgrade to Enterprise.

**Q: What are the key metrics to hit pre-raise?**

500+ GitHub stars, 100+ weekly pip installs, 3+ design partner conversations, 1+ LOI from a regulated company.

---

## 10. COMPETITIVE LANDSCAPE

**Q: Who are the direct competitors?**

| Company | Status | Why we are different |
|---|---|---|
| Guardrails AI | Independent, $7.5M seed | Complex setup, no self-serve pricing, no MCP awareness. We are simpler DX, self-serve. |
| Lakera (Check Point) | Acquired | Enterprise-only, no developer self-serve, no longer independent. We are independent, accessible. |
| CalypsoAI (F5) | Acquired | Government-only, no developer self-serve. We are developer-first. |
| NVIDIA NeMo Guardrails | Open source toolkit | Requires self-hosting, no managed service, no compliance layer. We integrate with them and add forensic governance on top. |
| Galileo | Funded, independent | Observability-first, guardrails second. We are security-first. |

**Q: What about the RSA 2026 wave?**

| Company | What they do | Why we are different |
|---|---|---|
| AQtive Guard (SandboxAQ) | AI-SPM: discovery, guardrails, EU AI Act reporting | Enterprise CSPM play, not developer-first |
| Miggo Security | Runtime defense: AI-BOM, behavioral drift, MCP monitoring | Runtime observability, not policy enforcement or forensic evidence |
| Cisco AI Defense | Zero Trust for agents, MCP policy enforcement | Enterprise networking stack, not standalone SDK |
| GuardionAI | Unified agent runtime security | Early stage, less developer focus |
| Bifrost/Maxim | AI gateway with guardrails, OpenTelemetry | Gateway-centric (infra layer), not SDK-centric (code layer) |

**Q: What is our positioning in one sentence?**

The only independent, developer-first AI runtime security platform with self-serve pricing that covers the full agentic lifecycle: detection, verification, explanation, containment, and cross-agent trust. We are not a gateway and not an observability tool. We are the forensic evidence layer.

**Q: How do we differentiate from prevention tools?**

Prevention tools (Lakera, NeMo Guardrails, Bedrock Guardrails) try to stop bad things from happening. They own the pre-incident layer. Nobody owns the post-incident forensic and incident response layer. That is what we own. And with Layer 3 (containment), we also prevent in real time, but our prevention is bound to authenticated human identity, not just rules.

---

## 11. TECHNICAL ARCHITECTURE

**Q: What is the repo structure?**

Monorepo with four main surfaces:

| Path | What | License |
|---|---|---|
| `packages/projectair/` | The public MIT package (`air` CLI + `airsdk` library). This is the product. | MIT |
| `packages/projectair-pro/` | Licensed commercial tier (`projectair-pro`, `airsdk_pro` namespace). Premium detectors, premium reports, AIR Cloud client. | Commercial |
| `src/vindicara/` | Engine substrate (policy engine, MCP scanner, agent IAM, monitor, compliance, API, dashboard, CDK infra). | Apache-2.0 |
| `site/` | Marketing and pricing site (SvelteKit 2 + Svelte 5 + Tailwind 4). | N/A |
| `packages/air-dashboard/` | AIR Cloud dashboard (SvelteKit 2 + Svelte 5 + Tailwind 4 + Three.js). | N/A |

Pitch the split as: "MIT CLI + SDK top-of-funnel, commercial pro tier + engine behind the cloud."

**Q: What is the tech stack?**

- **SDK/CLI:** Python 3.12+, Pydantic, Typer, BLAKE3, cryptography (Ed25519 + ML-DSA-65 + ECDSA P-256), PyJWT, rfc3161-client, sigstore, fpdf2, PyYAML
- **Backend API:** FastAPI, Mangum (Lambda adapter), DynamoDB, S3, EventBridge
- **Infrastructure:** AWS CDK (Python), Lambda + API Gateway, CloudFront + S3 (static site)
- **Frontend (marketing site):** SvelteKit 2, Svelte 5, Tailwind 4, static adapter
- **Frontend (dashboard):** SvelteKit 2, Svelte 5, Tailwind 4, Three.js, static adapter
- **Quality:** mypy --strict, ruff, pytest with 80% coverage floor

**Q: How does Vindicara self-host AIR?**

Vindicara runs Project AIR on its own production infrastructure. Every API request is a signed AgDR record anchored to public Sigstore Rekor. The trust contract matches customer chains exactly. Code lives in `src/vindicara/ops/`, middleware in the FastAPI layer, CDK stack for deployment.

**Q: Where is the infrastructure hosted?**

AWS. Vindicara, Inc. C-Corp account (ID: 399827112476), region us-west-2. Site served via CloudFront + S3. API runs on Lambda + API Gateway. DynamoDB for structured logs, S3 for audit trail storage, EventBridge for real-time events. Migration from the prior SLTR account (335741630084) is nearly complete.

---

## 12. RELEASE HISTORY

| Version | Date | Headline |
|---|---|---|
| 0.1.x | April 2026 | Initial release. BLAKE3 + Ed25519 chain. LangChain/OpenAI/Anthropic. First 7 detectors. |
| 0.2.x | April 2026 | ASI05-ASI09 detectors. LlamaIndex integration. |
| 0.3.0 | 2026-04-22 | 10/10 OWASP Agentic. ASI03/ASI10 Zero-Trust. Agent registry. Article 72 reports. |
| 0.3.1 | 2026-04-23 | LlamaIndex integration. |
| 0.3.2 | 2026-05-01 | Google Gemini SDK + Google ADK integrations. NVIDIA NIM verified. |
| 0.4.0 | 2026-05-06 | Layer 1: RFC 3161 + Sigstore Rekor anchoring. Live Rekor proof. |
| 0.5.0 | 2026-05-07 | Layer 2: Causal reasoning. `air explain`. |
| 0.6.0 | 2026-05-07 | Layer 3: Containment with Auth0-verified human-in-the-loop. |
| 0.6.1 | 2026-05-07 | Auth0 device flow, PKCE, `air approve` CLI. |
| 0.7.0 | 2026-05-07 | Layer 4 Wave 1: AgDR Handoff Protocol (cross-agent trust). |
| 0.7.1 | 2026-05-07 | Pricing alignment. |
| 0.8.0 | 2026-05-11 | ML-DSA-65 post-quantum signatures (experimental). |
| 0.8.1 | 2026-05-11 | Date-range filtering on compliance reports. |
| 0.9.0 | 2026-05-12 | NVIDIA NeMo Guardrails + NemoGuard NIM integrations. 16 total detectors. |

---

## 13. ROADMAP

**Q: What is next after 0.9.0?**

Near-term:
- Layer 4 Wave 2: cross-tenant federation via Sigstore Fulcio + OIDC Discovery.
- Layer 4 v1.5: private/enterprise federation (Okta, Entra, Spiffe adapters go live).
- Layer 1 v0.4.1: anchoring key rotation with key transparency log.
- Learned-baseline ASI10 variant (statistical profiling, peer comparison).
- Full ASI04 Agentic Supply Chain detector (dependency poisoning, tool-manifest tampering).
- Framework integrations: CrewAI, AutoGen, AG2.
- LangChain/OpenAI tool-call interceptor wrappers (automatic containment without manual `tool_start` calls).
- AIR Cloud: hosted ingestion, incident dashboard, SIEM export.

Longer-term (NVIDIA Tiers 3-4):
- Air-gapped NIM-packaged deployment for regulated enterprises (6-12 months).
- GPU-accelerated forensic search across massive trace corpora (12+ months).

**Q: What is the launch status?**

Public launch (Hacker News, LinkedIn) is postponed pending California incorporation completion. No specific date is set. The product is live on PyPI and vindicara.io is live. The launch is a marketing event, not a product gate.

---

## 14. QUALITY STANDARDS

**Q: What quality gates apply to every feature?**

Four gates, established as company discipline:

1. **End-to-End Proof:** Runnable demo a customer can execute in under 60 seconds.
2. **Test Coverage Proof:** Measured numbers in release notes. 80% floor enforced by CI.
3. **Deployment/Readiness Boundary:** Explicit experimental/beta/production label on docs, pricing page, and CLI surface.
4. **Customer-Facing Value:** One-sentence customer-language description before engineering starts. If you cannot write it, the feature is not ready to scope.

**Q: What is the code quality bar?**

- mypy --strict. No `Any` types.
- No bare `except`.
- No `print` in production paths.
- 300 lines max per file.
- ruff for linting and formatting.
- Root cause fixes only. No band-aids.
- For untrusted input: no dynamic code evaluation, no unsafe deserialization, no unsafe YAML loaders.

---

## 15. KEY URLS AND ARTIFACTS

| What | Where |
|---|---|
| Website | https://vindicara.io |
| PyPI package | https://pypi.org/project/projectair/ |
| Dashboard | https://vindicara.io/dashboard/ |
| Pricing | https://vindicara.io/pricing |
| Admissibility whitepaper | https://vindicara.io/admissibility |
| Blog | https://vindicara.io/blog |
| Rekor proof (Layer 1) | https://search.sigstore.dev/?logIndex=1455601514 |
| Rekor proof (Layer 4) | https://search.sigstore.dev/?logIndex=1465403522 |
| Auth0 tenant (Layer 3/4 demo) | dev-kilt2vkudvbu75ny.us.auth0.com |

---

## 16. THINGS NOT TO SAY

These are phrases and claims that have been explicitly caught and corrected:

- Do not say "years of security tooling experience" about Kevin. He is a cybersecurity student.
- Do not say "anomaly detection" about ASI10. It is Zero-Trust behavioral-scope enforcement.
- Do not say "Merkle chain." The chain uses BLAKE3 content hashes, not a Merkle tree.
- Do not say "the incident layer is empty." The chain is not empty; it records everything.
- Do not say "artifacts write themselves." We write them. The automation is explicit.
- Do not say "three warm design partner conversations" unless verified with real names.
- Do not conflate AIR-04 (chain integrity) with ASI10 (behavioral scope). They are different detectors with different purposes.
- Do not use em dashes in any written material. Use commas, semicolons, colons, or separate sentences.
- Do not claim "court-admissible" as a guarantee. The architecture is designed for admissibility. Whether a court admits specific evidence is a legal question.

---

## 17. BRAND AND NAMING

**Q: What is the brand hierarchy?**

- **Vindicara** = the company
- **Project AIR** = the flagship initiative (use on hero pages, pitch decks, whitepapers, legal documents, press, investor materials)
- **AIR** = shorthand in code, docs, CLI, and technical copy where brevity matters
- **AIR SDK, AIR Cloud, AIR Enterprise** = product tier names (developer-facing)
- `air`, `airsdk`, `vindicara`, `projectair` = technical artifacts (package names, imports, CLI commands)

**Q: What is the design system?**

Dark tactical aesthetic. Sharp corners. No purple SaaS gradients. JetBrains Mono for data surfaces. No italic display serif (Instrument Serif, Playfair, etc.), no gradient text, no magazine masthead accents. Default to Inter 800, tight tracking, for headlines.

---

## 18. PARTNERSHIPS AND PROGRAMS

| Program | Status | Scope |
|---|---|---|
| NVIDIA Inception | Member since April 2026 | Website badge only (by Kevin's decision). Unlocks DGX Cloud credits, NIM packaging support, ecosystem visibility. |
| Auth0 Startup Program | Targeted | Technical integration shipped (Layer 3). Marketplace listing is a follow-up artifact. |
| YC S26 | Applied | Application submitted. 1-minute founder video recorded. |

---

## 19. WHAT "ADMISSIBLE BY DESIGN" MEANS IN PRACTICE

The full trust chain looks like this:

1. Agent makes a decision (LLM call, tool call, message).
2. AIR records it as a Signed Intent Capsule (BLAKE3 hash + Ed25519/ML-DSA signature + chain link to previous record).
3. Every N steps or N seconds, the chain root is anchored to RFC 3161 (trusted timestamp from an independent TSA) and Sigstore Rekor (public transparency log with Merkle inclusion proof).
4. If a high-stakes action is detected, containment halts the agent and requires Auth0-verified human approval. The approval is recorded on-chain with the authenticated identity (JWT claims).
5. If the agent delegates to another agent, Layer 4 propagates the trace ID, exchanges capability tokens, and records the handoff with a Rekor counter-attestation.

The result: an unbroken, externally verifiable, tamper-evident record of everything the agent did, why it did it, who authorized the risky parts, and how the chain of custody was maintained across agent boundaries. No party (including Vindicara) can alter it after the fact. Any third party can verify it using only public infrastructure.

That is what "Admissible by Design" means. The evidence is designed to meet the standards for admissibility from the moment it is created, not retrofitted after an incident.
