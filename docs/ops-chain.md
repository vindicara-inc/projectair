# Vindicara ops chain

Vindicara dogfoods Project AIR for its own production audit trail. Every API request and (post-launch) every dashboard auth event is recorded as a signed AgDR record using the same `airsdk` library customers use. Each chain is anchored to public Sigstore Rekor. The chain catalog is published as redacted JSONL at `https://vindicara.io/ops-chain/` and is independently verifiable via `air verify-public`.

This document is for operators (right now: Kevin, post-launch: any Vindicara employee) and for external auditors who want to verify the claim "Vindicara runs Project AIR on its own infrastructure."

## Trust model

The signature on each record was produced **inside the Lambda that emitted it**, at the moment of the action, not by a downstream reconstruction process. This is the same trust contract customers get with AIR. There is no alternative system tailing logs and synthesizing AgDR records after the fact: the Lambda runtime calls `airsdk.AIRRecorder` directly, and the resulting signed records land in DynamoDB.

Anchoring is async. A separate cron Lambda batches complete chains and submits their roots to Rekor on a 60-second cadence. The publisher (also a separate cron Lambda) reads anchored chains, applies the per-kind redaction policy, and writes JSONL to S3.

## How to verify a chain yourself

```
pip install projectair
curl https://vindicara.io/ops-chain/<chain-id>.jsonl > /tmp/chain.jsonl
air verify-public /tmp/chain.jsonl
```

(URL support directly in the CLI is a follow-up in projectair 0.7.2 / 0.8.0; today the CLI takes a local path.)

This runs the same five-step verifier any customer would run on a production AIR chain:

1. Walks the chain forward, recomputing each record's `content_hash` from the payload and asserting the signature against the embedded `signer_key`.
2. Asserts each record's `prev_hash` equals the previous record's `content_hash`.
3. Resolves the chain root (last record's `content_hash`) and the `rekor_log_index` referenced in the chain.
4. Fetches the inclusion proof from public Rekor and verifies it cryptographically.
5. Confirms the inclusion proof binds the chain root to the log index recorded in the chain.

Zero Vindicara infrastructure is contacted during verification. The trust roots are Sigstore Rekor's signed tree head, which is independently audited.

## Why bodies are redacted

The internal chain (in DynamoDB) keeps full payload fidelity. The published chain has every payload field replaced by `"blake3:" || hex_digest` of the original value's canonical-JSON encoding, **unless** the field appears in the per-kind whitelist in `src/vindicara/ops/schema.py`.

Whitelisted fields per kind:

| Kind | Public fields |
|---|---|
| `vindicara.api.request` | `method`, `path_template`, `status_code`, `duration_ms` |
| `vindicara.dashboard.auth.*` | `outcome`, `duration_ms` |
| `vindicara.ops.*` | `outcome`, `approver_sub`, `duration_ms` |

Everything else (request bodies, headers, user identifiers, IP addresses, JWT tokens, anything we cannot prove is safe) is hashed. The signatures cover the unredacted records on the internal chain; the published JSONL is for narrative + chain-ordering verification, and the Rekor anchor binds the chain root.

A property-based test (`tests/unit/ops/test_redaction.py::test_no_denylist_field_leaks_into_public`) asserts that no field whose name matches `token`, `secret`, `password`, `email`, `ip`, etc. ever appears in the published JSONL except as a hash. The test runs 200 random payload shapes per CI run.

## Operator runbook

### Anchorer is falling behind

Symptom: Sigstore log index on the public manifest is older than 5 minutes, or stale-chain alarm fires.

1. Check the anchorer Lambda's CloudWatch Logs for the `vindicara.ops.anchorer.anchor_failed` event. Most likely cause: Rekor outage. Confirm at https://search.sigstore.dev.
2. If Rekor is up: check that the Lambda has internet egress (it should not be in a VPC).
3. If the issue is a Lambda code bug: redeploy. Chains in DynamoDB are durable. Any chain queued during the outage will anchor on the next successful run.
4. If the backlog grows past `MAX_CHAINS_PER_INVOCATION`, increase the cadence to once every 30 seconds in `ops_chain_stack.py` or temporarily bump the cap.

### Publisher is falling behind

Symptom: anchored chains are not appearing at `vindicara.io/ops-chain/`.

1. Check the publisher Lambda's CloudWatch Logs for `vindicara.ops.publisher.publish_failed`.
2. Most likely cause: S3 bucket policy regression. Confirm via `aws s3api get-bucket-policy --bucket vindicara-ops-chain-public-<account>` that the public-read-on-prefix statement is intact.
3. If a bad publish corrupts a JSONL: the publisher is idempotent. Delete the offending S3 object; on the next cron tick, the publisher re-emits it from the still-marked-anchored DDB rows by setting `published=False` (manual DDB update needed; it is not auto-rewriting on its own).

### A record needs to be retracted

This should be very rare: regulatory deletion request, accidental PII leak past redaction, etc. The chain is append-only, so true deletion is not possible without invalidating the chain. The procedure:

1. Confirm with legal that retraction is required and that the resulting "chain has a missing block" public signal is acceptable.
2. Delete the offending S3 object from `vindicara-ops-chain-public-<account>/ops-chain/<chain-id>.jsonl`.
3. Emit a public attestation explaining the retraction (signed by Vindicara) and link it from the manifest.
4. The chain root in DDB and Rekor remains; the public proof of retraction is also anchored to Rekor as its own chain.

This is intentional: a forensic-grade audit trail must not silently rewrite history. Retraction with public notice is the only operation that preserves the trust model.

### Break-glass: operator CLI lockout

If Auth0 misconfiguration locks operators out of the gated CLI actions (key revoke, DSAR fulfill, redaction policy change), there is a break-glass procedure documented in the operator CLI itself: a local-signed offline-emergency-key file at `~/.config/vindicara/break_glass_key.pem` (mode 0600) bypasses the Auth0 step-up and records a loud `EMERGENCY_OVERRIDE` event in the chain. Requires the file to physically exist on the operator's machine; designed so its existence is itself an audit signal.

The break-glass key is rotated every 90 days and stored offline.

## Architecture: where each piece lives

| Component | Path | Responsibility |
|---|---|---|
| Recorder helpers | `src/vindicara/ops/recorder.py` | `OpsRecorder` wrapper, `request_chain` context manager |
| DDB transport | `src/vindicara/ops/ddb_transport.py` | Implements `airsdk.transport.Transport`; writes to DDB |
| Schema | `src/vindicara/ops/schema.py` | Event kinds, redaction whitelist, denylist field names |
| Redaction | `src/vindicara/ops/redaction.py` | Applies per-kind whitelist at publish time |
| Anchorer | `src/vindicara/ops/anchorer.py` | Cron Lambda: scans complete chains, submits to Rekor |
| Publisher | `src/vindicara/ops/publisher.py` | Cron Lambda: writes redacted JSONL to public S3 |
| API middleware | `src/vindicara/api/middleware/ops_chain.py` | FastAPI middleware bracketing every request |
| CDK stack | `src/vindicara/infra/stacks/ops_chain_stack.py` | DDB, S3, two cron Lambdas |
| Local E2E | `scripts/e2e_ops_chain.py` | Offline smoke test of the full pipeline |
| Public page | `site/src/routes/ops-chain/+page.svelte` | Live manifest fetch + verify instructions |

## Costs (run-rate at launch traffic)

At ~1,000 API requests / day:

| Resource | Cost / month |
|---|---|
| DynamoDB on-demand (writes + scans) | < $1 |
| Anchorer Lambda invocations | < $0.50 |
| Publisher Lambda invocations | < $0.50 |
| S3 storage + requests | < $1 |
| CloudWatch Logs (1y retention) | ~$1 |
| Rekor (public good service) | $0 |

Total ~$5 / month. The build is the expensive part, not the run.
