# Changelog

All notable changes to `projectair-pro` are documented here. Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Versioning: [SemVer](https://semver.org/).

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
