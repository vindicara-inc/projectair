# Changelog

All notable changes to `projectair-pro` are documented here. Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Versioning: [SemVer](https://semver.org/).

## [0.6.0] - 2026-05-08

First real premium detector lands. Closes the "Premium detectors as they ship" line on the public pricing page with a real implementation: three new sub-detectors under OWASP **ASI04 Agentic Supply Chain Vulnerabilities** that go deeper than the OSS MCP-naming-convention check. The ASI04 surface in OSS was honest about being partial coverage (only MCP names); this release adds the dependency-poisoning and tool-manifest-tampering signals that the OSS roadmap committed to.

### Added
- `airsdk_pro.detectors.detect_supply_chain_premium(records)`: runs three sub-detectors and returns `Finding` objects in the same shape the OSS package emits, so existing reports and exports consume them unchanged. Gated behind the new `premium-detectors` Pro feature flag.
  - **ASI04-PD Dependency Install Surface** (`severity=high`): flags tool calls that invoke a package manager (pip, npm, pnpm, yarn, gem, cargo, go install, apt-get, yum, brew, dnf) or a remote shell pipe (`curl … | bash`, `wget … | sh`, `… | python`).
  - **ASI04-TM Tool Manifest Drift** (`severity=medium`): flags the same `tool_name` appearing with diverging argument schemas across the chain. Requires at least 2 prior calls with a stable schema before the third call introducing new keys triggers the finding, so optional-key usage does not produce false positives.
  - **ASI04-USF Untrusted Source Fetch** (`severity=high`): flags tool args that fetch executable content from sources commonly used to bypass dependency review (raw GitHub, gists, pastebins, ngrok / localhost.run / serveo tunnels, transfer.sh, 0x0.st).
- `airsdk_pro.detectors.run_premium_detectors(records)`: convenience wrapper that runs every premium detector this release ships. Future releases add more sub-detectors under other OWASP categories without breaking callers of this entrypoint.
- `airsdk_pro.PREMIUM_DETECTORS_FEATURE` and `airsdk_pro.PREMIUM_DETECTOR_IDS` for programmatic discovery of the surface.
- `air detect-premium <log> [--output findings.json]` CLI subcommand. Same defer-the-import pattern as the other Pro CLI commands so OSS-only installs still expose the help text and emit a clean install message at runtime. Stdout shows a per-detector count summary plus the individual findings.
- 32 new tests in `tests/test_detectors_asi04_premium.py`: per-detector positive coverage with parametrised pattern matrices (17 install patterns, 8 untrusted-host patterns), benign-traffic negatives, manifest-drift threshold and per-tool-name isolation, the aggregate `run_premium_detectors` entrypoint, and gate rejection for both no-license and missing-feature cases.

### Notes
- ASI04-TM is the first detector in the family that operates over chain history rather than per-record; it tracks per-`tool_name` schema state and only triggers after at least 2 prior calls with a stable key set, so a tool that gains a key the first time it is called will not produce a false positive.
- The OSS `detect_mcp_supply_chain_risk` MCP-naming-convention check is unchanged and continues to ship in the free tier.

## [0.5.0] - 2026-05-08

Wave 2 starts. Closes the "AIR Cloud client SDK (push capsules to a hosted workspace)" line on the public pricing page with a real implementation. Today the client targets storage the **customer** owns (HTTPS webhook or S3 bucket); the hosted multi-tenant Vindicara ingest service is a follow-on release. The client surface is stable across that transition: when the hosted service ships, the same APIs gain a default endpoint and authentication path, but the wire format does not change.

Why customer-owned destinations first:
- It makes "AIR Cloud client" a real shipping feature now, not a stub.
- It works air-gapped and in regulated tenants without any Vindicara control plane in the data path.
- It defers the multi-tenant question (auth, billing, retention, data residency) until the hosted service is ready, instead of locking customers into a half-built ingest API.

### Added
- `airsdk_pro.cloud` submodule with two destinations, both gated behind the new `air-cloud-client` Pro feature flag:
  - `push_chain_to_webhook(records, *, url, secret=None, extra_headers=None, ...)`: POSTs the chain as newline-delimited JSON (one AgDR record per line, signatures intact for offline re-verification with `air trace`). When `secret` is set, the body is HMAC-SHA256-signed and the digest is sent as `X-Vindicara-Signature: sha256=<hex>` so the receiver can reject tampered or unauthenticated requests. Same envelope pattern GitHub, Stripe, and Slack outgoing webhooks use.
  - `push_chain_to_s3(records, *, bucket, key, region=None, sse="AES256", metadata=None, ...)`: uploads the JSONL chain to a customer-owned S3 bucket via boto3. Server-side encryption defaults to `AES256`. `metadata` keys land in S3 object metadata. boto3 is an **optional** dependency: install `projectair-pro[s3]` to enable S3, or stick with the base install and use the webhook destination.
- `airsdk_pro.CloudPushResult`, `airsdk_pro.CloudConfigError`, `airsdk_pro.CloudPushError` for structured success and failure handling.
- `airsdk_pro.AIR_CLOUD_CLIENT_FEATURE` license feature flag.
- `air cloud push-webhook` and `air cloud push-s3` CLI subcommands wired in `projectair.cloud_cli`. Same defer-the-import pattern as the SIEM commands so OSS-only installs still expose the help text and emit a clean install message at runtime. Common config env vars supported (`AIR_CLOUD_WEBHOOK_URL`, `AIR_CLOUD_WEBHOOK_SECRET`, `AIR_CLOUD_S3_BUCKET`, `AIR_CLOUD_S3_KEY`).
- 19 new tests in `tests/test_cloud_push.py` covering: webhook JSONL ordering with one line per record, HMAC-SHA256 signing path with externally-recomputed digest, secret-omitted no-signature path, `extra_headers` merge, refusal to override `Content-Type` or the signature header from `extra_headers`, empty-chain short-circuit, missing-config rejection, non-2xx escalation, S3 `put_object` argument shape (Bucket / Key / ContentType / ServerSideEncryption / Metadata), `sse=None` opt-out path, helpful `CloudConfigError` message when boto3 is not installed, and gate-rejection for both no-license and missing-feature cases on each destination.

### Changed
- `projectair-pro` now declares an optional `[s3]` extra (`pip install projectair-pro[s3]`) that pulls in `boto3>=1.34,<2.0`. Webhook destination works without it.

### Notes
- Wave 2 continues with a real premium detector (full ASI04 supply-chain) and incident workflows / alerting (Slack, PagerDuty, generic webhook). Hosted AIR Cloud ingest service is W3.

## [0.4.0] - 2026-05-08

Wave 1 closes. Closes the "SIEM integrations: Datadog, Splunk, Sumo, Sentinel" line on the public pricing page with real implementations: thin HTTPS push helpers that take a Project AIR `ForensicReport` and deliver each detector finding directly to a customer-owned SIEM. Vindicara is never in the data path; every push goes from the customer's process straight to the customer's SIEM endpoint.

### Added
- `airsdk_pro.siem` submodule with four push helpers, all gated behind the new `siem-integrations` feature flag:
  - `push_to_datadog(report, *, api_key, site=DEFAULT_DATADOG_SITE, source, service, tags, min_severity, ...)`: Datadog Logs API v2 (`https://http-intake.logs.<site>/api/v2/logs`). Each finding becomes one log entry tagged with `detector_id:<id>`, `severity:<level>`, `air_version:<v>`. EU / US3 sites covered via the `site` parameter.
  - `push_to_splunk_hec(report, *, hec_url, hec_token, sourcetype, source, index, min_severity, ...)`: Splunk HTTP Event Collector. Constructs the concatenated-JSON-envelope format HEC actually expects (NOT a JSON array). Optional `index` for engagements with per-team Splunk indexes.
  - `push_to_sumo(report, *, http_source_url, category, host, name, min_severity, ...)`: Sumo Logic Hosted HTTP Source. Newline-delimited JSON, with optional `X-Sumo-Category` / `X-Sumo-Host` / `X-Sumo-Name` metadata headers.
  - `push_to_sentinel(report, *, workspace_id, shared_key, log_type, min_severity, ...)`: Microsoft Sentinel via Azure Log Analytics Data Collector API. Computes the SharedKey HMAC-SHA256 signature locally so the workspace key never leaves the customer's process; `log_type` defaults to `VindicaraAIR` (Sentinel auto-appends `_CL`).
- `airsdk_pro.SiemPushResult`, `airsdk_pro.SiemConfigError`, `airsdk_pro.SiemPushError` for structured success and failure handling.
- `airsdk_pro.SIEM_INTEGRATIONS_FEATURE` license feature flag.
- `air siem datadog|splunk|sumo|sentinel <log>` CLI subcommands wired in `projectair.siem_cli`. Each defers the `airsdk_pro` import to the command body so OSS-only installs still expose the help text and emit a clean install message at runtime. Common credential env vars supported (`DD_API_KEY`, `SPLUNK_HEC_URL`, `SPLUNK_HEC_TOKEN`, `SUMO_HTTP_SOURCE_URL`, `SENTINEL_WORKSPACE_ID`, `SENTINEL_SHARED_KEY`).
- 17 new tests in `tests/test_siem_push.py` using `httpx.MockTransport`: per-vendor success path, endpoint URL correctness (Datadog default vs EU site, Splunk URL passthrough, Sumo URL, Sentinel `<workspace>.ods.opinsights.azure.com`), payload-format invariants (Datadog JSON array, Splunk concatenated JSON envelopes, Sumo NDJSON, Sentinel JSON array), authentication shape (`DD-API-KEY`, `Authorization: Splunk <token>`, Sentinel `SharedKey <ws>:<sig>` with HMAC-SHA256 verified independently against the canonical Microsoft signing string), `min_severity` filtering, empty-findings short-circuit, missing-config rejection (`SiemConfigError`), non-2xx escalation (`SiemPushError`), gate rejection for both no-license and missing-feature cases.

### Changed
- `httpx>=0.27,<1.0` is now a direct runtime dependency of `projectair-pro`. The OSS `projectair` package already pulls httpx transitively (Layer 3 Auth0 integration) so this is a hoist, not a new wheel cost.

### Notes
- Wave 1 complete: NIST AI RMF (`0.2.0`), SOC 2 AI (`0.3.0`), and the SIEM push helpers (`0.4.0`) all ship before any of these surfaces are re-enabled on the public pricing page.
- Wave 2 starts next with the AIR Cloud client v0 (push to a customer-owned webhook / S3 bucket), one real premium detector, and incident workflow / alerting hooks (Slack, PagerDuty, generic webhook).

## [0.3.0] - 2026-05-08

Second premium report ships. Closes the "Premium reports: SOC 2-AI" line on the public pricing page with a real implementation. The output is auditor-input evidence material structured against the AICPA Trust Services Criteria, NOT a SOC 2 report (only an independent CPA can issue one); the disclaimer is explicit on this distinction.

### Added
- `airsdk_pro.report_soc2_ai.generate_soc2_ai_report(...)`: deterministic Markdown evidence template structured against the AICPA TSC categories in scope (Common Criteria / Security and, where elected, Processing Integrity). Includes a TSC crosswalk that maps Project AIR's signed-chain evidence to CC2.1, CC4.1, CC4.2, CC6.1, CC6.6, CC7.2, CC7.3, CC7.4, CC7.5, CC8.1, CC9.1, PI1.4, PI1.5.
- `airsdk_pro.SOC2_AI_FEATURE`: the license feature flag (`"report-soc2-ai"`) the generator gates on.
- `air report soc2-ai <log> --system-id <id> [--service-organisation ...] [--in-scope ...]` CLI subcommand. Same graceful-degradation pattern as `nist-rmf`: clean install message when projectair-pro is absent, license error when the active license lacks the entitlement.
- 15 new tests in `tests/test_report_soc2_ai.py` mirroring the NIST RMF coverage: header rendering, "not a SOC 2 report" disclaimer enforcement, chain-OK and chain-tampered statements (with CC7/CC8 references), TSC crosswalk completeness, severity rollup arithmetic, in-scope-categories rendering, attestation version reference, appendix completeness, pipe-escaping, time-range, signer-key truncation, default placeholders, and gate-rejection behaviour for both no-license and missing-feature cases.

### Notes
- Discipline holds: this release adds SOC 2 AI only. Wave 1 closes after the SIEM push helpers ship next (Datadog HEC, Splunk HEC, Sumo, Sentinel) as `0.4.0`.

## [0.2.0] - 2026-05-08

First premium feature lands behind the existing license gate: the NIST AI RMF (NIST AI 100-1) risk-management report generator. Closes the "Premium reports: NIST AI RMF" line on the public pricing page with a real implementation.

### Added
- `airsdk_pro.report_nist_rmf.generate_nist_rmf_report(...)`: deterministic Markdown report structured against the four AI RMF functions (GOVERN, MAP, MEASURE, MANAGE), populated from a Project AIR signed Intent Capsule chain. Includes a subcategory crosswalk that maps Project AIR's signed-chain evidence onto the AI RMF subcategories it directly supports (GOVERN 1.5, GOVERN 4.2, MAP 5.1, MEASURE 1, MEASURE 2.7, MEASURE 2.8, MEASURE 3, MANAGE 1.3, MANAGE 4.1).
- `airsdk_pro.NIST_RMF_FEATURE`: the license feature flag (`"report-nist-ai-rmf"`) the generator gates on.
- `air report nist-rmf <log> --system-id <id>` CLI subcommand. Lives in the OSS `projectair` CLI; gracefully prints the install/upgrade message when `projectair-pro` is not installed and a clear license error when the active license lacks the entitlement.
- 14 new tests in `tests/test_report_nist_rmf.py`: header rendering, disclaimer presence, chain-OK and chain-tampered statements, subcategory crosswalk completeness, severity rollup arithmetic, critical/high finding placement, attestation version reference, appendix completeness and pipe-escaping, observed time-range, signer-key truncation, default placeholder behaviour, gate rejection when no license is installed, and gate rejection when the license lacks the `report-nist-ai-rmf` feature.

### Changed
- `projectair` runtime dependency range bumped from `>=0.3.1,<0.5` to `>=0.7.1,<0.8` to match the current OSS release line (Layers 1-4 forensic stack).
- Output disclaimer is explicit that NIST does not certify or attest to AI RMF conformance, so the generated report is an evidence template, not a "NIST-blessed" artefact.

### Notes
- Disciplined scope: this release adds NIST AI RMF only. SOC 2 AI report ships next as `0.3.0`.
- The `air-cloud-client` and `premium-detectors` feature flags remain license-only namespaces with no implementation behind them yet; do not advertise them on the public pricing surface until the corresponding code lands.
