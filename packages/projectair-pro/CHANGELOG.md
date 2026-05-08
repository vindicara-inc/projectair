# Changelog

All notable changes to `projectair-pro` are documented here. Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Versioning: [SemVer](https://semver.org/).

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
