# Design: Vindicara ops chain (dogfood AIR for our own Lambda + dashboard)

Status: draft, 2026-05-08
Owner: Kevin
Goal: ship a publicly verifiable Vindicara ops chain anchored to Sigstore Rekor, before the public launch, so the launch can credibly say "we use our own product on our own infrastructure."

## What we are building

Every Vindicara API request and every dashboard auth event becomes an AgDR record in a Vindicara-operated chain. The chain is signed (Layer 0), anchored to Sigstore Rekor on the customer-default cadence (Layer 1), and gates a small set of high-risk operator actions on a verified Auth0 step-up (Layer 3). The chain file is published with redacted bodies; the Rekor anchors are public; anyone can run `air verify-public` against the published chain.

This is the SOC 2 logging control, prebuilt. It is also a launch-day artifact no competitor has.

## What we are not building

- No real-time UI on top of the chain. The chain is the source of truth; visualization is a separate effort.
- No Layer 4 handoff between Vindicara services in v1. We can add PTID propagation later; not on the critical path.
- No custom retention controls. Chain stays in S3 with the same lifecycle as the existing audit bucket.

## The trust-model decision (the one-way door)

Customer AIR chains are signed **at the moment of action**, in-process, with the agent's key. That binding — signature time = action time = in-process state — is the heart of the forensic claim. Any architecture that signs after the fact (for instance, by tailing CloudWatch Logs and reconstructing AgDR records from log lines) is a different chain than what we sell. The launch claim "we run our own product on our own infrastructure" becomes technically false unless we attach a footnote, and the footnote dulls the asset.

So the architecture matches customer semantics 1:1: **sign in-process, anchor async**. Each Lambda invocation produces a short signed chain. Chains land in DynamoDB. A separate worker batches and anchors to Rekor.

At our actual traffic (~1k req/day), the perf objections to in-process signing don't apply: Ed25519 sign is ~50µs and DDB single-record writes from same-region Lambda are ~5-10ms. We're solving for scale we don't have if we shed signature fidelity.

## The architecture: in-process sign, async anchor

```
   Lambda (api) per invocation                              Cron Lambda (every 30s)
   ┌──────────────────────────────┐                         ┌────────────────────────┐
   │ AIRRecorder(transport=DDB)   │                         │ scan unanchored chains │
   │   request_start (signed)     │                         │ build BLAKE3 root      │
   │   ... handler logic ...       │ ──► DDB ops chain  ──► │ anchor to Rekor        │
   │   request_end (signed)       │     (ord, parent,       │ write Rekor index back │
   │   transport.flush()          │      hash, sig per row) │ to DDB                 │
   └──────────────────────────────┘                         └────────────────────────┘
                                                                       │
   Dashboard auth (FastAPI)                                             ▼
   ┌──────────────────────────────┐                          Cron Lambda (every 60s)
   │ same AIRRecorder pattern     │                          ┌────────────────────────┐
   │ chain per auth event         │ ──► DDB ops chain ─────► │ publish redacted JSONL │
   └──────────────────────────────┘                          │ to public S3 + manifest│
                                                             └────────────────────────┘
                                                                       │
                                                                       ▼
                                            https://vindicara.io/ops-chain/<id>.jsonl
                                            (verify with: air verify-public <url>)
```

**Per-invocation chain.** Each Lambda invocation has its own short chain (typical: `request_start`, optionally a `tool_start`/`tool_end` pair if a sub-call is interesting, `request_end`). Signed in-process by `AIRRecorder` against an `airsdk.transport` implementation that writes to DynamoDB instead of files. Chain catalog is many short chains, not one giant chain.

This sidesteps the concurrency problem (no global `parent_hash` race between Lambdas) and matches customer semantics — customers run one agent per chain too. The "Vindicara ops chain" externally is a *catalog* of per-invocation chains.

**DDBTransport (new module).** Implements `airsdk.transport.Transport` writing each AgDR record to a DynamoDB table partitioned by chain-id (the Lambda invocation id) with sort key `ord`. Records carry their full signature; reads reconstruct the chain in order. ~5-10ms per record write at our region.

**Anchoring (cron Lambda, ~30-60s cadence).** Reads chains marked `complete=true` (request_end seen) and `anchored=false`. For each, computes BLAKE3 root over the chain in canonical order, anchors to public Sigstore Rekor (`RekorClient` with `Prehashed` semantics, exactly as `airsdk.anchoring` does for customers), writes the returned `log_index` back into the chain row. Rekor cost is free; Lambda cost rounds to zero at 1k req/day.

**Publication (cron Lambda, ~60s cadence).** Reads anchored chains, redacts per-kind, writes to a public-read S3 bucket as JSONL. Updates a `manifest.json` with the most recent log index. The vindicara.io `/ops-chain/` page hits the manifest.

**Concurrency model.** Each cron Lambda is configured with `reserved_concurrency=1` (advisor: "don't try to scale this; just write it once and move on"). One anchoring writer, one publishing writer, no DDB-head contention.

**No CloudWatch subscription filter, no log tailing.** The hot path goes straight from `AIRRecorder` to DDB. Trust model identical to customer chains.

## Layer 3 containment for operator actions

Three operator actions get gated on Auth0 step-up. They run in a small "ops-cli" runner that we (Kevin) invoke locally; they don't run inside the Lambda:

1. **Revoke an API key for a user other than self.** Requires Auth0 JWT with `vindicara:keys.revoke` scope.
2. **Fulfill a DSAR (export + delete user data).** Requires Auth0 JWT with `vindicara:privacy.fulfill` scope.
3. **Modify the public-chain redaction policy.** Requires Auth0 JWT with `vindicara:ops.policy_change` scope.

Each gated action emits a `HUMAN_APPROVAL` record into the same chain as a permanent audit trail of who approved what. This uses `airsdk.containment.Auth0Verifier` exactly as built. Vindicara's tenant: `dev-kilt2vkudvbu75ny.us.auth0.com`.

## Components and where they live

```
src/vindicara/ops/
  __init__.py
  schema.py          # canonical event kinds + payload shapes (request_start, request_end, auth.login, auth.mfa, ...)
  recorder.py        # thin wrapper: opens AIRRecorder per Lambda invocation with DDBTransport + the right key
  ddb_transport.py   # NEW: implements airsdk.transport.Transport, writes signed records to DDB
  redaction.py       # field-redaction policy (replace by BLAKE3 hash); declarative table per kind; default-deny
  anchorer.py        # cron Lambda handler: scans complete-but-unanchored chains, runs RekorClient, writes index back
  publisher.py       # cron Lambda handler: reads anchored chains, redacts, writes JSONL + manifest to public S3
  policy.py          # Layer 3 containment policy for the operator step-up
  cli.py             # vindicara-ops cli: revoke-key, fulfill-dsar, change-redaction (gated on Auth0 step-up)
  tests/
    test_ddb_transport.py
    test_redaction.py
    test_anchorer.py
    test_publisher.py
    test_policy.py
    test_e2e_local.py

src/vindicara/infra/stacks/
  ops_chain_stack.py  # NEW: anchorer cron Lambda, publisher cron Lambda, public S3 bucket, DDB ops-chain table

scripts/
  e2e_ops_chain.py    # local E2E: spin up fake AIRRecorder against DDB local → anchorer → publisher → verify-public

docs/
  ops-chain.md        # operator-facing docs: how to verify Vindicara's own chain

site/src/routes/ops-chain/+page.svelte   # public verify page on vindicara.io
```

The Lambda handler integration touches `src/vindicara/lambda_handler.py` (wrap `Mangum` with a per-invocation recorder context) and `src/vindicara/dashboard/auth/middleware.py` (emit `auth.login` / `auth.mfa` / etc. into the same chain catalog).

## Cost envelope

- CloudWatch Logs ingestion: ~$0.50/GB ingested. At 1k req/day with ~1KB log lines, ~30MB/month. Negligible.
- Assembler Lambda: invoked on log batches, ~1 invocation per batch. Probably under $1/month at launch traffic.
- DDB chain-state: single-row updates, on-demand pricing. Under $1/month.
- S3 storage: chain files compress well (mostly hashes). Under $1/month at launch.
- Rekor: free public good service.

Total run cost at launch: ~$5/month. The expensive part is build time, not run time.

## Risks and mitigations

| Risk | Mitigation |
|---|---|
| Anchorer falls behind and chains stay unanchored. | DDB scan filter on `complete=true AND anchored=false`. Stale-chain alarm: any chain older than 5 minutes still unanchored fires the same SNS topic that Lambda errors do. |
| Rekor outage during anchoring window. | Anchorer retries with exponential backoff up to 1 hour. Chains are durable in DDB; nothing is lost. The published manifest still serves last-known-good. |
| Redaction policy lets a secret leak into the public chain. | Redaction is whitelist-by-kind: only fields explicitly marked `public: true` in `schema.py` are emitted unredacted. Default deny. Hypothesis property test: emit 1000 randomized records, assert no field with name in a denylist (`token`, `secret`, `password`, `key`, `email`, `ip`) appears in the published JSONL except as `BLAKE3(...)`. |
| Auth0 tenant misconfiguration locks Kevin out of the operator CLI. | Break-glass procedure: a local offline-emergency-key file (mode 0600 in `~/.config/vindicara/break_glass_key.pem`) signs a `EMERGENCY_OVERRIDE` record into the chain in lieu of an Auth0 token. The file's existence is itself a loud audit signal. |
| Public chain reveals traffic patterns. | Per-request fields are hashed. Aggregate-only fields (`kind`, `timestamp`, `chain_id` if cryptographically random) emit clear. The chain proves *that* events happened in *which order*, not *what was in them*. |
| Lambda invocation dies between `request_start` and `request_end`. | Chain is marked `complete=false`. Anchorer ignores incomplete chains. A separate sweeper marks chains older than 5min as `terminated_no_end` and anchors them with that marker — this is itself a public signal of incomplete request handling. |
| DDB write fails inside the handler. | Recorder has a `failure_policy=Fail.SOFT` mode for the hot path (logs the failure, lets the request complete). The chain has a gap, AIR-04 will see it, that's the correct outcome — operator chooses available system over guaranteed chain. |

## Acceptance criteria for "shipped"

1. `air verify-public https://vindicara.io/ops-chain/<chain-id>.jsonl` returns success, including a Rekor inclusion proof for the latest anchor.
2. The vindicara.io public chain page shows a non-zero last-anchor index that updates within **60 seconds** of a request hitting prod (anchorer cadence + publisher cadence). Earlier criterion of "10 seconds" was wrong; advisor flagged it as inconsistent with the transport.
3. Anchorer + publisher cron Lambdas have run continuously for at least 48 hours before launch with no stale-chain alarms and no anchoring failures.
4. The operator CLI's three gated actions reject wrong-issuer / expired / wrong-scope Auth0 tokens, and accept only correctly-issued ones; both paths write a record to the chain.
5. Redaction tests pass under hypothesis with 1000 randomized records and zero denylist-field leaks into the public JSONL.
6. ruff + mypy --strict + pytest matrix green across `src/vindicara/ops/`.
7. CHANGELOG entry on `vindicara` 0.3.0.
8. **Trust-model statement** documented at `docs/ops-chain.md`: "Vindicara's ops chain uses the same `airsdk.AIRRecorder` library that customers use, signing in-process at the moment of each event. Anchoring is async via a separate cron Lambda. The signature on each record was produced inside the Lambda that emitted it."

## Sequencing (target: live + bedded-in by 2026-05-12, slip-friendly)

| Day | Work |
|---|---|
| **Friday 2026-05-08 (today)** | Design doc (this) signed off. Cut branch `ops/dogfood-air-chain`. Stand up `src/vindicara/ops/` skeleton. Write `schema.py` + `ddb_transport.py` + `recorder.py`. Unit tests for transport. |
| **Saturday 2026-05-09** | `redaction.py` + hypothesis tests. `anchorer.py` + `publisher.py`. Local E2E (`scripts/e2e_ops_chain.py`) drives the full pipeline against DDB local + a mocked Rekor. |
| **Sunday 2026-05-10** | `ops_chain_stack.py` (CDK). Deploy alongside existing stacks. Wire `lambda_handler.py` + `dashboard/auth/middleware.py` to use the recorder. Drive synthetic traffic, confirm chains land, anchor, publish. |
| **Monday 2026-05-11** | `policy.py` + `cli.py` for operator step-up. Public chain page on vindicara.io. Open the soak window. |
| **Tuesday 2026-05-12** | Continued soak. Decide: 48h minimum from Sunday-deploy means launch is **earliest Tuesday afternoon**. If anchorer or publisher hiccups before then, launch slips. |
| **Wed/Thu 2026-05-13/14** | Slip buffer (treat as P(slip) ≥ 0.6 per advisor — built-in, not a surprise). |

Slip behaviour: if Sunday's deployment misses, launch slips to Wed. If Monday misses, launch slips to Thu. If Tuesday's soak shows any anchor failure, launch slips. **Slip is the default, not the exception.**

## Decisions locked (no follow-up needed)

- Public chain at path `https://vindicara.io/ops-chain/` on the existing CloudFront — fewer DNS moving pieces this close to launch.
- Three Auth0 scopes fresh in the existing tenant: `vindicara:keys.revoke`, `vindicara:privacy.fulfill`, `vindicara:ops.policy_change`.
- Ships under `vindicara` 0.3.0.
