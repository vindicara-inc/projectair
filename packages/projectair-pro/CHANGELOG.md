# Changelog

All notable changes to `projectair-pro` are documented here. Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Versioning: [SemVer](https://semver.org/).

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
