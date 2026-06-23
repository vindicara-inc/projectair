# Pressure-Test Fixes Applied

Date: 2026-06-22. All 13 findings from PRESSURE_TEST_2026-06-22.md are addressed. Verification at the end of this file. No em dashes used (repo rule).

## Verification summary

- Full test suite: 705 passed, 4 deselected (network/integration), proxy disabled. Up from 699; the rise is the new regression tests below.
- ruff check src: all checks passed.
- `air demo`: runs in under a second, still proves byte-level tamper-evidence (verification fails at the exact mutated record).
- Demos: Layer 3, Layer 4 (mock IdP), attestation, key-rotation all pass; Layer 1 now exits cleanly offline.
- `air attest` now exists; `air upgrade` shows the site pricing; both version constants read 1.2.0.
- F4 graceful degradation proven: with ML-DSA simulated absent, Ed25519 still signs/verifies and ML-DSA raises a clear RuntimeError.

## The fixes

1. README detector/layer counts (F1). Root `README.md` rewritten to match the PyPI README and the code: five-layer stack (added Layer 5 Data Governance), 16 detectors (10 + 3 + 3), AIR-05/AIR-06 listed, badge corrected to Python 3.10+, `site/` reference corrected to `vindicara-site/`.

2. Layer 4 verifier fail-closed (F2). `CrossAgentVerifier` gained `require_capability_token_jwt` (the `air handoff verify` CLI defaults it True, with `--allow-unverified-token` to opt into the sidecar model). When a handoff carries no issuer-signed JWT, strict mode now fails instead of silently passing. New `VerificationResult.jwt_reverified` records whether the JWT was actually re-verified, and the CLI surfaces a PARTIAL warning when it was not, so a green result can never hide a skipped check. The overclaiming docstrings and the dead `b64decode` retention line were removed. Tests added: `test_strict_mode_fails_without_raw_jwt`, `test_permissive_mode_flags_unverified_token`.

3. validation_proof Rekor check (F3). Removed the no-op `pass`. Added `RekorBackend.verify_inclusion`: the stub backend now confirms the exact canonical bytes were submitted and that the anchor coordinates bind to those bytes; the live backend fails closed on a proof missing its anchor coordinates or anchored state. The docstring is corrected to state honestly that the proof is an agent-signed, coordinate-bound attestation, and that full Merkle inclusion re-verification happens via the Layer 1 `air verify-public` path (the proof carries only a hash of the inclusion proof by privacy design).

4. cryptography pin reconcile (F4). Core pin moved from `>=48.0.0,<49.0` to `>=42.0.0,<47.0`, matching the 1.0.1 CHANGELOG and keeping the core install broadly resolvable. Added a `[pqc]` extra for `cryptography>=48`. The hard ML-DSA import in `recorder.py` was made conditional (it would have broken `import airsdk` on older cryptography). ML-DSA requests on older cryptography now raise a clear RuntimeError with an upgrade hint; Ed25519 is unaffected.

5. Pricing to site truth (F5). `air upgrade` and CLAUDE.md now mirror the site's retention-metered model: Free $0, Pro $45/mo, Team Talk to us, Enterprise Talk to us. The old flat Individual $39 / Team $599 wording is gone.

6. air attest registration (F6). `cli.py` now registers `attest_cli`, so `air attest` exists as the release notes claimed.

7. projectair version (F7). `projectair/__init__.py` corrected from 0.1.6 to 1.2.0.

8. CLAUDE.md refresh (F8). Current-state block updated to 1.2.0 and AgDR v0.7, with the cryptography floor, the `[pqc]` extra, the Layer 4 fail-closed posture, the `meta_signed` change, and the retention-metered pricing folded in. The 1.1.0 and 1.2.0 features are summarized.

9. Em dashes (F9). Removed from the two PyPI/GitHub-shipped files: `README.md` (0 now) and `CHANGELOG.md` (0 now). Note: the live site (vindicara-site) still contains em dashes in many component, CSS, and blog files; that is a larger, separate cleanup left as a follow-up since it risks touching CSS/JS content, and the site's factual claims are already consistent.

10. PyPI classifier (F10). `Development Status` bumped from 4 - Beta to 5 - Production/Stable.

11. Sign more record fields (F11). Records now bind step_id, timestamp, kind, and signature_algorithm into the signature via a new additive `meta_signed` flag. New records set it True; legacy records (and the published reference anchors) verify over prev_hash + content_hash exactly as before. The flag is self-protecting: flipping it on a signed record invalidates the signature. Tests added for timestamp tamper, kind tamper, flag-strip, and legacy compatibility.

12. jti replay + OCSP (F12). `AIRRecorder.approve()` now keeps a single-use jti ledger and rejects a replayed approval token with `ApprovalInvalidError`. `GPUAttestationConfig` gained `require_ocsp`, so a missing cached OCSP reference can be made a hard failure for deployments that must enforce revocation (default keeps the documented W1 behavior).

13. Layer 1 fail-open clarity (F13). The fail-open anchoring default is already a deliberate, configurable `FailurePolicy` (per-action fail-closed overrides plus backlog promotion), so that design is sound. `e2e_layer1.py` now accepts the documented `--live-tsa` / `--live-rekor` flags and, run without them, prints how to enable live anchoring and exits 0 instead of a confusing fail-open exit 1.

## One item intentionally not mass-changed

The live site still uses em dashes in many files. Replacing them site-wide is a larger sweep that can touch CSS/JS and blog copy, so it is flagged as a follow-up rather than done blind here. The site's factual claims (16 detectors, five layers, retention-metered pricing) are already correct and consistent for the investor meeting.
