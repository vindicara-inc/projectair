# Project AIR — Consolidated Roadmap

Pulled 2026-06-01 from every roadmap source in the repo. Baseline release: `projectair` 1.0.1 (2026-05-25).

---

## Sources pulled

- `CLAUDE.md` — "Roadmap (next)" section
- `docs/SPEC.md` — GTM sequence, pricing tiers, fundraise, success milestones
- `docs/pitch/cofounder-qa.md` — §13 Roadmap, §8 NVIDIA four-tier roadmap, Layer 4 Wave status
- `docs/pitch/icc-deck-content.md` — use-of-funds engineering plan
- `docs/pitch/air_deck.md` and `docs/pitch/Vindicara_Pitch_Deck.md` — 90-day weekly milestones, GTM
- `docs/pitch/accelerator-applications.md` — revenue milestones
- `packages/projectair/CHANGELOG.md` — shipped OSS history
- `packages/projectair-pro/CHANGELOG.md` — Pro Wave 1/2/3 (AIR Cloud) history
- `docs/superpowers/specs/*.md` — forward-looking "Future / Phase 2" sections
- `MIGRATION_PLAN.md` — AWS account cutover

### Not pulled (outside accessible folder)

These memory files exist but live in `~/.claude/projects/.../memory/`, which is outside the connected folder. To fold them in, copy them into the repo (e.g. a `memory/` subfolder) and I'll merge them:

- `project_roadmap.md`
- `project_nvidia_partnership_roadmap.md`
- `project_framework_integration_roadmap.md`
- `project_launch_state.md`
- `project_aws_migration.md`
- `project_layer4_design_decisions.md`
- `feedback_four_quality_gates.md`
- `MEMORY.md`

---

## 1. Shipped (baseline, as of 1.0.1)

Five-layer architecture complete. Detector count 16 (10 OWASP Agentic + 3 OWASP LLM + 3 AIR-native).

- **Layer 0 Detection** — all 10/10 OWASP Agentic (ASI01-ASI10), 3 OWASP LLM (AIR-01/02/03), 3 AIR-native (AIR-04 chain integrity, AIR-05/06 NemoGuard).
- **Layer 1 External Trust Anchor** (0.4.0) — RFC 3161 + Sigstore Rekor; `air anchor`, `air verify-public`.
- **Layer 2 Causal Reasoning** (0.5.0) — `air explain`.
- **Layer 3 Containment** (0.6.0) — Auth0-verified human-in-the-loop approval.
- **Layer 4 Handoff Protocol Wave 1, alpha** (0.7.0) — cross-agent chain of custody, single-tenant, Auth0-only, eight-step verifier. Demonstrated live 2026-05-07.
- **Layer 5 Data Governance, Pro** (1.0.0) — AgDR v0.6, DSAR, OpenLineage.
- **Structural Verification** (1.0.0) — `verify_intent`, IntentSpec, `air verify-intent`.
- **ML-DSA-65 post-quantum signatures** (0.8.0, experimental opt-in; conditional import since 1.0.1).
- **NVIDIA integrations** (0.9.0) — NeMo Guardrails telemetry + NemoGuard NIM classifiers.
- **Framework integrations** — LangChain, OpenAI, Anthropic, LlamaIndex, Gemini, Google ADK, NeMo Guardrails (+ any OpenAI-compatible endpoint).
- **Pro / AIR Cloud (commercial)** — Wave 1 (premium detectors, reports), Wave 2 (SIEM push: Splunk/Datadog/Sentinel/Sumo/Slack; incident alerting: Slack/PagerDuty/webhook), Wave 3 started (hosted multi-tenant ingest service `cloud.vindicara.io`, capsule ingest/list/verify API, workspace + API-key management).
- **Vindicara ops-chain** (vindicara 0.3.0) — dogfooded signed chain on own production infra; public catalog at `vindicara.io/ops-chain/`.

---

## 2. In-flight / uncommitted

- **`projectair` 1.0.1** — relaxes `cryptography` to `>=42.0.0,<47.0`; conditional ML-DSA imports; adds `betterproto`. (Listed as in-flight in CLAUDE.md; CHANGELOG dates it 2026-05-25.)
- **Pro hosted AIR Cloud** — DynamoDB-backed `WorkspaceStore` / `ApiKeyStore` / `CapsuleStore` + CDK wiring land in a follow-on release (the in-memory factory is dev-only today).
- **Admin/OIDC gating (W3.10)** — `POST /v1/workspaces` must be gated behind an admin path or OIDC login before public exposure.

---

## 3. Product / engineering roadmap — near-term

Consolidated from `cofounder-qa.md §13` and `CLAUDE.md`:

- **Layer 4 Wave 2** — cross-tenant federation via Sigstore Fulcio + OIDC Discovery. Lifts the single-tenant feature flag once Wave 1 has one reference deployment. *(This is the real moat; currently unshipped.)*
- **Layer 4 v1.5** — private/enterprise federation: custom CA roots, archived JWKS, live Okta / Entra / Spiffe adapters (currently interface-only placeholders raising `IdPNotImplementedError`).
- **Layer 1 v0.4.1** — anchoring key rotation with key transparency log; bundled TSA root cert set; `docs/anchoring.md` + `docs/threat-model.md`.
- **Learned-baseline ASI10** — statistical behavioral profile + peer comparison (requires training-data collection). The shipped ASI10 is Zero-Trust scope enforcement, not anomaly detection.
- **Full ASI04 Agentic Supply Chain** — beyond MCP naming patterns: dependency poisoning, tool-manifest tampering.
- **Framework integrations** — CrewAI; AutoGen (MS v0.4+ and AG2 fork as separate targets); A2A protocol capture tracked as a new surface area.
- **LangChain / OpenAI tool-call interceptor wrappers** — automatic containment without manual `tool_start` calls (deferred from Layer 3).
- **AIR Cloud** — hosted ingestion + dashboard + SIEM export backing the Team tier; NeMo Guardrails ingestion lands in Phase 1.5.

---

## 4. Product / engineering roadmap — mid / long-term

From the superpowers design specs and the NVIDIA tiers:

- **NVIDIA Tier 3** (6-12 mo) — air-gapped NIM-packaged deployment for regulated enterprises. Depends on AIR Cloud baseline GA.
- **NVIDIA Tier 4** (12 mo+) — GPU-accelerated forensic search across massive trace corpora. Requires customers ingesting at volume.
- **Data Governance v2** — counterfactual replay ("what if we removed subject X's data?"); regulation-specific report packs (HIPAA Breach Notification, GDPR Article 30 RoPA, CCPA); persistent governance index with search. *(spec: 2026-05-18-data-governance-module-design.md)*
- **AgDR canonicalization Phase 2** — ciphertext-bearing subject fields + crypto-shredding; possible v0.7 opt-in. *(spec: 2026-05-18-agdr-canonicalization-merkle-design.md)*
- **Sealed Report Verification Phase 2** — content-aware staleness; per-subject envelope encryption. *(spec: 2026-05-18-sealed-report-verification-design.md)*
- **Identity Capture Phase 2** — beyond the shipped Phase 1. *(spec: 2026-05-25-identity-capture-design.md)*
- **MCP Security Scanner Phase 3** — out-of-scope items deferred from v1. *(spec: 2026-03-31-mcp-security-scanner-design.md)*

---

## 5. Vertical bets

- **Healthcare** — HL7v2 + FHIR R4 Clinical Evidence Sidecar (draft v3, post-review); HIPAA Safe Harbor 18-identifier redaction; BAA; identity capture for clinical agents. First 3 paying health-system pilots are a stated use-of-funds goal. *(spec: 2026-05-25-hl7v2-fhir-siem-gateway-design.md)*
- **Insurance** — Armilla partnership (first call is a 90-day milestone); insurance-carrier evidence integrations as an Enterprise feature; AI insurance market framed as "evidence inputs" buyer.

---

## 6. GTM / business phases

From `SPEC.md`:

1. **Phase 1 (launch)** — ship OSS; Admissibility-by-Design page (FRE 901/902(13)/803(6) mapping); HN + LinkedIn + outbound. Target: 500 stars, 100 weekly installs in 90 days; warm 3-5 design partners.
2. **Phase 2 (day 60)** — AIR Cloud Team tier live; first paying customer; 3+ design-partner conversations by day 90.
3. **Phase 3 (6 mo, Nov 2026)** — AIR Cloud GA; SOC 2 Type I observation begins; 10+ paying Team teams.
4. **Phase 4 (12 mo, May 2027)** — Enterprise tier live (branded evidence, SSO/SAML, on-prem); SOC 2 Type I done/near; 50+ paying teams; first enterprise contract; Series seed pitch-ready.

90-day weekly milestones (from `air_deck.md`):

- Week 1 — 10/10 OWASP Agentic shipped; OWASP Q3 Solutions Landscape submission.
- Week 4 — AIR Cloud private alpha; EchoLeak case-study blog; 3 design-partner LOIs (EU + US).
- Week 8 — first paid pilot ($5K-$15K/mo); 500 GitHub stars; Armilla first call; OWASP contributor status.
- Week 12 — $40K-$75K MRR run-rate; 5 paying customers; seed open.

ICP / wedge (from the deck): security engineer at a Series A-C agentic shop (LangChain / LlamaIndex / ADK) with at least one EU customer demanding Article 72 readiness; ~500-1,200 reachable buyers.

24-month vision (`SPEC.md`): category-defining independent platform; fintech / healthtech / govtech enterprise logos; Series A ready.

---

## 7. Fundraise

Inconsistent across documents (resolve before pitching):

- `SPEC.md` and `cofounder-qa.md`: **$500K SAFE at $5M post-money cap.**
- `air_deck.md`: **$500K SAFE at $5M cap**, "12 months to design-partner revenue."
- `icc-deck-content.md`: **$750K pre-seed** (50% engineering / 30% GTM / 20% ops).
- Pre-raise metrics: 500+ stars, 100+ weekly installs, 3+ design-partner conversations, 1+ LOI from a regulated company.

---

## 8. Infrastructure / ops roadmap

- **AWS account migration** (`MIGRATION_PLAN.md`) — SLTR `335741630084` (us-east-1) → Vindicara C-Corp `399827112476` (us-west-2). Three hardcoded references to update: `data_stack.py`, `deploy-site.sh`, GitHub Actions workflow.
- **Public ops-chain URL** stabilizes once `OpsChainStack` deploys against the new account.
- **SOC 2 Type I** — controls observation begins Phase 3 (Nov 2026), targeted complete/near by Phase 4.

---

## 9. Contradictions to resolve (surfaced by pulling everything together)

These conflict across documents and will undercut diligence if left inconsistent:

1. **Launch status.** `cofounder-qa.md` says the public launch is "postponed pending California incorporation, no date set." Your account is that the launch already happened and went badly. Reconcile which is true and update the docs to match.
2. **Team-tier price.** $1,499/mo (`SPEC.md`, current) vs $599/mo (`CLAUDE.md` 0.7.1 note) vs $49 Dev / $149 Team self-serve (`air_deck.md` GTM slide). Pick one public number.
3. **Raise amount.** $500K vs $750K across decks.
4. **Detector count.** `icc-deck-content.md` still says "14 OWASP detectors"; current ground truth is 16 (10 + 3 + 3). The ICC deck is stale.
5. **Phase-1 detector framing.** `SPEC.md` Phase 1 says "10 of 10 OWASP Agentic + 3 LLM + 1 AIR-native"; current is 3 AIR-native. SPEC GTM predates the 0.9.0 detectors.
