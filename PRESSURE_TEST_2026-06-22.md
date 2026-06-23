# Project AIR / Vindicara: Pressure Test

Date: 2026-06-22. Scope: claims-vs-reality audit, test + demo execution, crypto/fail-closed red-team. Method: ran the real suite and demos in a clean Linux/Python 3.10 env (editable install of `packages/projectair[dev]`, `cryptography 48.0.1`), plus live proof-of-concept exploits and a full doc/code cross-check. No production network calls.

## Verdict

The core product is real and holds up well. The detection layer, the chain-integrity story, key custody, containment, and the single-agent `air demo` are all genuinely solid and pass live testing. The exposure is concentrated in two places: (1) a set of public-claim inconsistencies that a diligence reviewer or Hacker News reader would catch in minutes, and (2) the Layer 4 cross-agent verifier, where the "fail-closed cross-agent trust" language is not matched by the verification code on the common deployment path. Layer 4 Wave 1 is labelled alpha, which contains the blast radius, but the docstrings and copy overstate the guarantee.

## What is solid (verified live)

- Test suite is genuinely green: 699 passed, 3 skipped with the sandbox proxy disabled. The 5 failures + 15 errors on first run were 100% environmental (a `socks5h://localhost:1080` proxy the sandbox injects plus one live-FreeTSA network test), not product defects.
- Coverage measured at 88% on `airsdk`, above the claimed 80% floor.
- Detector count matches the mandated framing exactly: code implements 10 ASI + 6 AIR = 16, with `UNIMPLEMENTED_DETECTORS` empty. AIR-05 and AIR-06 (NemoGuard) are real functions.
- `air demo` runs in 0.3s, classifies findings, exports JSON/PDF/CEF, and proves byte-level tamper-evidence by failing verification at the exact mutated record. The under-60-second quality gate is real.
- Layer 3, Layer 4 (mock IdP), attestation (fixture), and key-rotation e2e demos all pass in under one second.
- Crypto contracts that hold as claimed: chain integrity catches reorder/drop/tamper; key custody catches a forged key takeover (`UNAUTHORIZED_KEY`) while integrity stays green by design; deny rules override step-up; Auth0 verification is alg-confusion resistant (RS256/384/512 only, no `none`/HS256) and `approve()` fails closed on forged/expired/wrong-issuer tokens; `reconcile_channels`, `canonicalize`, `AdapterRouter` (no blind OIDC fallback), and two-bound temporal ordering all fail closed; the NRAS attestation nonce binds to the delegation genesis so a replayed EAT on a different session fails closed.

## Findings by severity

### CRITICAL / HIGH (fix before launch)

1. Root `README.md` is stale and undercounts the product. It says "14 detectors / 1 AIR-native / four-layer stack". Code and the PyPI README say 16 / 3 AIR-native / five layers. This is the GitHub front page and it contradicts your own PyPI page. Fix: rewrite the detector table to "10 OWASP Agentic + 3 OWASP LLM + 3 AIR-native = 16 total", list AIR-05/AIR-06, and align to five layers.

2. Layer 4 cross-agent verifier reports `passed=True` while skipping capability-token verification. In `handoff/verifier.py` (step 5, lines ~415-435), when `raw_jwt` is absent from the handoff record (which the format explicitly allows, and the docstring says production "typically omits"), the verifier calls `result.flag(...)` instead of verifying the token. `flag()` never sets `passed=False`; only `fail()` does. So on the common path the chain set is reported valid having never checked the token signature, issuer, audience, expiry, or the `air_*` claims. Pairing then rests on a `jti` string match. A malicious or compromised target agent can fabricate a `handoff_acceptance`, sign it with its own LOCAL_DEV key, and pass verification. The leftover `_ = b64decode # retained for future raw-JWT verification path` confirms the real path was never wired. Fix: when `raw_jwt` is absent and no out-of-band token verification is configured, `fail()` (not `flag()`); require the token to be verifiable.

3. Layer 4 "Rekor counter-attestation" is never checked against any transparency log at verify time. In `handoff/validation_proof.py` (`verify_validation_proof`, lines ~242-296), verification recomputes a blob hash and checks an Ed25519 signature made by the validating agent's own key over a blob that same agent authored: pure self-attestation. The `LiveRekorBackend` branch (~291-296) is a literal `pass` with a comment claiming Layer 1's `RekorClient.verify` does the inclusion check, but no such call exists. Combined with finding 2, a target agent forges a fully "valid" cross-agent handoff using only its own key. Fix: actually call the Rekor inclusion-proof verification, or stop describing this as independent proof in the copy until it does.

4. `cryptography` pin contradicts your own release note and breaks the graceful-degradation promise. `pyproject.toml:31` pins core `cryptography>=48.0.0,<49.0`, but CHANGELOG 1.0.1 (line 35) states this was broadened to `>=42.0.0,<47.0` specifically so Ed25519 keeps working on older cryptography and ML-DSA degrades with a clear error. The shipped pin reverts that fix and forces an OpenSSL-3.5-era cryptography on every core install. It installed fine here on Linux/py3.10 (a wheel exists), so it is not a universal break, but it contradicts the documented behavior and will fail on environments without a cryptography-48 wheel. Fix: reconcile the pin to `>=42.0.0,<47.0` and update the comment, or correct the 1.0.1 CHANGELOG if 48 is intentional.

5. Pricing has three different stories. Site `pricing/+page.svelte` shows Pro $45/mo and Team "Talk to us"; `air upgrade` (cli.py ~1065) is hardcoded to Individual $39/mo and Team $599/mo; CLAUDE.md mandates $39/$599. A user runs `air upgrade`, sees $39/$599, clicks to the site, sees $45/"Talk to us". Fix: pick one source of truth and reconcile site, CLI, and memory.

6. `air attest` is release-noted but not wired into the CLI. CHANGELOG 1.1.0 claims "CLI: new `air attest` (experimental)". The command exists in `projectair/attest_cli.py` but `cli.py` never registers it (every sibling module is registered via a `_register_*` call; attest is missing). Confirmed live: `air attest --help` returns "no such command". Fix: add the `_register_attest_cli(app)` call.

7. `projectair.__version__` reports `0.1.6` while `airsdk.__version__` and `pyproject.toml` are `1.2.0`. Confirmed at runtime. Fix: set `projectair/__init__.py` to `1.2.0`.

### MEDIUM / LOW

8. CLAUDE.md "current state" is stale: it says 1.0.0 / 1.0.1 in-flight and AgDR schema v0.6, but the tree is at 1.2.0 and `AGDR_VERSION = "0.7"`. This is working memory, not shipped, but it is steering you wrong. Fix: update to 1.2.0 / v0.7 and fold in the 1.1.0 features (key custody, delegation, GPU attestation, NeMo toolkit handoff, Layer 4 Wave 2).

9. Em dashes in shipped copy violate your own hard rule. One in `README.md:37`, nine in `CHANGELOG.md`. The PyPI README is clean (zero). Fix: replace with commas/colons in the two GitHub/PyPI-shipped files at minimum.

10. PyPI Development Status classifier is "4 - Beta" (`pyproject.toml:15`) while 1.0.0 declares production. A reviewer reading the classifier sees Beta on a "production" 1.2.0.

11. `signature_algorithm`, `kind`, `step_id`, and `timestamp` are outside the signed material (signature covers `prev_hash || content_hash` only). Algorithm downgrade is blocked today only by Ed25519 vs ML-DSA key-size mismatch, an accident rather than an explicit binding; forensic timestamps are mutable without breaking `verify_record`. Fix: fold these fields into the signed material.

12. `approve()` has no `jti` single-use ledger: the same still-valid Auth0 token could clear multiple distinct pending challenges before expiry. Attestation OCSP check skips (does not fail) when no cached OCSP is configured. Both low severity and partly documented as open decisions.

13. Layer 1 e2e is not zero-setup-offline like the others: it requires a live TSA (FreeTSA) and "fails open" when unreachable. Worth confirming the fail-open anchoring default is intentional and documented, since a silent anchor failure on a forensic product is a story a reviewer could spin.

### Verifiable claims a reviewer can independently check (collect and confirm before launch)

Public copy cites Rekor log indices 1455601514 (Layer 1) and 1465403522 (Layer 4), a live Auth0 tenant `dev-kilt2vkudvbu75ny.us.auth0.com`, and an Azure NCCads H100 v5 NRAS attestation (honestly hedged as experimental with `RIM_BUNDLE_NOT_FOUND`). The code paths that produce each exist. Confirm the Rekor entries resolve and the ops-chain S3 bucket is actually public before the README invites `curl`. A live `dev-*` Auth0 tenant named in public copy is a minor exposure worth retiring.

## Priority order

1. Layer 4 verifier and validation-proof gap (findings 2, 3): either wire the verification or downgrade the cross-agent fail-closed language to match alpha reality.
2. Root README detector count and layer count (finding 1): front-page, flatly wrong.
3. `cryptography` pin vs CHANGELOG (finding 4): test a clean `pip install projectair` on a stock environment.
4. Pricing reconciliation (finding 5).
5. `air attest` registration (finding 6) and `projectair.__version__` (finding 7).
6. CLAUDE.md refresh, em dashes, classifier (findings 8, 9, 10).
