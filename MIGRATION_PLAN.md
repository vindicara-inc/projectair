# Vindicara / Project AIR — AWS Account Migration Plan

**Generated:** 2026-04-28 (Phase 1 discovery only, no resources modified).

**FROM:** account `335741630084` (SLTR Digital LLC), profile `default`, IAM `Kev-Dev`, region `us-east-1`.
**TO:** account `399827112476` (Vindicara, Inc.), profile `vindicara`, IAM `vindicara-air` (AdministratorAccess), region `us-west-2`.

**Cutover assumption to confirm:** no live paying customers; cleanliness > zero downtime.

---

## 0. Headline Findings

1. **The data layer is empty.** All three DynamoDB tables (`vindicara-policies`, `vindicara-evaluations`, `vindicara-api-keys`) report `ItemCount=0`. Audit S3 bucket holds 0 objects. There is no data to migrate, only infrastructure. This makes the migration drastically simpler than a normal account move.
2. **No cross-account-hard managed services.** No Cognito, no Aurora, no SES, no KMS CMKs of our own. The hard-to-migrate AWS services are absent. The only awkward asset is the Route 53 zone. (Update 2026-06-01: the AIR Cloud stack now creates one Secrets Manager secret, `air-cloud-admin-token`, for the W3.10 workspace-creation gate. It is self-contained: CDK auto-generates the value in whichever account the stack deploys to, so it carries no cross-account dependency. See §3a.)
3. **One hardcoded account ID in code.** `src/vindicara/infra/stacks/data_stack.py:47` pins `bucket_name="vindicara-audit-335741630084"`. The deploy script and GitHub workflow also pin `vindicara-site-335741630084`. These three references must change before deploy to the new account.
4. **The site (vindicara.io) is half-CDK, half-manual.** The Lambda + API Gateway + DynamoDB are CDK. The S3 site bucket, CloudFront distribution, ACM certs, and Route 53 zone are manually created. Migration is a good moment to either bring them into CDK or accept the manual model and document it.
5. **VindicaraData is currently `UPDATE_ROLLBACK_COMPLETE` in the old account** (last failed deploy 2026-04-09). Resources are alive (the rollback restored prior state) but the stack is stuck. Since we are abandoning the old account, this does not need to be fixed; it just needs to be deleted at the end.
6. **$1,000 of AWS Activate credits in the old account will not transfer.** Confirm with AWS Support if recovering credits matters before deleting old stacks.
7. **Bedrock Claude is available in `us-west-2`.** Sonnet 4.6, Haiku 4.5, Opus 4.7 all listed under `INFERENCE_PROFILE` plus on-demand variants of older models. The codebase does not currently call Bedrock, so this is informational only; if AIR Cloud Phase 1 ingestion later adds Bedrock-based summarization, the new region supports it.
8. **No live paying customers.** Per user-stated assumption. Re-confirm before Phase 2.

---

## 1. Resource Inventory (old account)

### 1a. CDK-managed (`src/vindicara/infra/stacks/`)

| Resource | Type | Stateful? | Region-locked? | New region | Migration method | Risk |
|---|---|---|---|---|---|---|
| `vindicara-policies` | DynamoDB Table | Yes (currently empty) | Regional | us-west-2 | Recreate via CDK (no data export) | Low |
| `vindicara-evaluations` | DynamoDB Table | Yes (currently empty, has TTL attr) | Regional | us-west-2 | Recreate via CDK | Low |
| `vindicara-api-keys` | DynamoDB Table | Yes (currently empty) | Regional | us-west-2 | Recreate via CDK | Low |
| `vindicara-audit-335741630084` | S3 Bucket | Yes (currently empty, versioned, lifecycle to IA→Glacier) | Regional | us-west-2 | Recreate via CDK with new name `vindicara-audit-399827112476` (code change required, see §3) | Low |
| `vindicara-events` (EventBridge bus) | EventBridge | No (stateless routing) | Regional | us-west-2 | Recreate via CDK | Low |
| `vindicara-log-evaluations` | EventBridge Rule | No | Regional | us-west-2 | Recreate via CDK | Low |
| `vindicara-api` | Lambda (Python 3.13, Mangum) | No | Regional | us-west-2 | Recreate via CDK; requires `lambda_package/` build artifact (currently absent) | Low |
| API Gateway HTTP v2 `d1xzz26fz4` | API Gateway | No | Regional | us-west-2 (new ID) | Recreate via CDK; **new endpoint URL** breaks CloudFront `/dashboard*` origin and any external integration referencing the old ID | Medium |
| `VindicaraAPI-APIFunctionServiceRole...` | IAM Role | No | Global | n/a | Recreated automatically by CDK in new account | Low |

### 1b. Manually-created (not in CDK)

| Resource | Type | Stateful? | Region | New region | Migration method | Risk |
|---|---|---|---|---|---|---|
| `vindicara-site-335741630084` | S3 Bucket (static-website-hosting) | Yes (68 objects, 1.76 MB; rebuildable from `npm run build`) | us-east-1 | us-west-2 (new bucket name `vindicara-site-399827112476`) | Recreate, run `npm run build && aws s3 sync` | Low |
| CloudFront `E2EIWI2GTEUFWW` | CloudFront Distribution | No (config only); aliases `vindicara.io`, `www.vindicara.io`; origins: S3 site + API Gateway | Global (config), edge cached | Global | Create new distribution in new account; cannot move a distribution between accounts | Medium |
| ACM cert `5688e99b...` | ACM Cert (in us-east-1, CloudFront-bound) | No (regenerable) | us-east-1 (CloudFront requires us-east-1) | us-east-1 (new account) | Re-issue in new account; DNS validation against vindicara.io zone | Low |
| ACM cert `57cf6783...` | ACM Cert (orphan, `InUseBy: []`) | No | us-east-1 | n/a | Do not migrate; delete in old account during cleanup | Low |
| Route 53 hosted zone `Z0749902KU2J4ZS2UQ4Z` | Hosted Zone (`vindicara.io.`) | Yes (DNS records) | Global | Global (new account) | Two options: (a) export records, create zone in new account, update registrar NS records; (b) leave zone in old account and only re-point alias targets. (a) is cleaner. | Medium |

### 1c. External / non-AWS

| Resource | Provider | Migration impact | Action |
|---|---|---|---|
| `projectair` PyPI package | PyPI | Out of scope per user. Owner email may still be SLTR account; no AWS coupling. | Note for follow-up: confirm `eng@vindicara.io` is owner; rotate `~/.pypirc` token if it was tied to old account email |
| `vindicara-inc/projectair` GitHub repo | GitHub | Already migrated (commit `6b0936e`) | None |
| GitHub Actions secrets `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY` | GitHub repo settings | Currently scoped to old account `Kev-Dev` user | Rotate to new-account creds (or switch to OIDC role assumption, recommended) |
| Domain registrar for `vindicara.io` | Porkbun (per memory) | Registrar holds the NS records that delegate to Route 53 | Update NS records at Porkbun if Route 53 zone moves accounts |
| Email forwarding (`legal@`, `privacy@`, etc.) | Porkbun forwarding → Gmail | Independent of AWS | None |
| Hosted mailbox `Kevin.Minn@vindicara.io` | Porkbun mailbox | Independent of AWS | None |

---

## 2. Dependency Graph (must move in this order)

```
Code changes (§3)
    │
    ├──► [a] cdk deploy VindicaraData (new account, new region)
    │         │
    │         ▼
    │   [b] cdk deploy VindicaraEvents
    │         │
    │         ▼
    │   [c] Build lambda_package + cdk deploy VindicaraAPI
    │         │
    │         ▼
    │   [d] Verify API Gateway responds (smoke test new endpoint)
    │
    └──► [e] Create new ACM cert in new account us-east-1 (DNS validate via existing zone or new zone)
              │
              ▼
        [f] Create new S3 site bucket + sync build output
              │
              ▼
        [g] Create new CloudFront distribution (origins: new S3 + new API GW from [c]; cert from [e])
              │
              ▼
        [h] DNS cutover at registrar: point vindicara.io to new CloudFront distribution
              │
              ▼
        [i] Verify live traffic on new endpoints for 24-48h
              │
              ▼
        [j] Decommission old account (reverse order: CF → S3 buckets → CFN stacks → ACM certs → Route 53 zone)
```

`[a]` through `[d]` and `[e]` through `[h]` can run in parallel after the code changes land. The choke point is `[h]` (DNS cutover) and depends on both branches.

---

## 3. Pre-Cutover Code Changes

The new account cannot deploy as-is. Three files have hardcoded references to the old account ID. None are runtime; all are build/deploy time.

| File | Line | Current | Change to |
|---|---|---|---|
| `src/vindicara/infra/stacks/data_stack.py` | 47 | `bucket_name="vindicara-audit-335741630084"` | Use `self.account` at synth time, or remove the explicit name and let CDK auto-name. Recommend `bucket_name=f"vindicara-audit-{self.account}"`. |
| `scripts/deploy-site.sh` | 11–12 | `vindicara-site-335741630084` / `E2EIWI2GTEUFWW` | New bucket + CF dist ID (filled in after step [f]/[g]) |
| `.github/workflows/deploy-site.yml` | 20–21 | same | same |

Also build the Lambda asset directory (`lambda_package/` does not exist in the working tree). The `cdk deploy` for `VindicaraAPI` calls `lambda_.Code.from_asset("lambda_package")` and will fail without it. Confirm whether there is a `make lambda` / build script we have not surfaced, or if the artifact is built ad-hoc.

### 3a. AIR Cloud admin-token secret (W3.10)

The AIR Cloud stack (`src/vindicara/infra/stacks/air_cloud_stack.py`) provisions the operator admin token that gates `POST /v1/workspaces`. Nothing to change for the migration; this is informational so the cutover does not surprise anyone.

- CDK creates a Secrets Manager secret `air-cloud-admin-token` with an auto-generated 48-char value (`generate_secret_string`). The value never appears in source or the CloudFormation template.
- The Lambda receives the secret ARN via the `AIR_CLOUD_ADMIN_TOKEN_SECRET_ARN` env var and is granted `secretsmanager:GetSecretValue` on that secret only. `factory._resolve_admin_token` reads it at cold start.
- Resolution precedence: explicit `admin_token` kwarg, then `AIR_CLOUD_ADMIN_TOKEN` env, then the secret ARN. If none resolve, workspace creation is disabled (503), never left open.
- A fresh deploy in the new account generates a fresh token automatically; there is no value to migrate. Operator runbook for fetching and using it: `docs/air-cloud-deploy.md`.

---

## 4. Cutover Checklist (Phase 2 — execute only after this plan is approved)

### Pre-flight
- [ ] User confirms: no live paying customers, cleanliness over zero-downtime.
- [ ] User decides: Route 53 zone migrate (option a) vs leave-in-old-account (option b).
- [ ] User decides: CloudFront / S3 site infra brought into CDK now, or stay manual.
- [ ] User decides: GitHub Actions deploy via OIDC (recommended) or rotated IAM keys.
- [ ] AWS Activate credits in old account: claim or accept loss before deletion.
- [ ] Snapshot the live API Gateway URL (`https://d1xzz26fz4.execute-api.us-east-1.amazonaws.com`) and CloudFront ID (`E2EIWI2GTEUFWW`) for rollback reference.

### Step 1 — Code changes (one PR)
- [ ] Update `data_stack.py:47` to use `f"vindicara-audit-{self.account}"`.
- [ ] Parameterize site deploy bucket + CF dist ID in `scripts/deploy-site.sh` and `deploy-site.yml`. Defaults can be the new values once known.
- [ ] Add a `scripts/build-lambda.sh` that produces `lambda_package/` reproducibly, or document the existing build command in `CLAUDE.md`.
- [ ] PR review, merge.

### Step 2 — Backend stacks in new account
- [ ] `cd /Users/KMiI/Desktop/vindicara`
- [ ] Build the Lambda package: `bash scripts/build-lambda.sh` (or equivalent).
- [ ] `VINDICARA_AWS_ACCOUNT_ID=399827112476 VINDICARA_AWS_REGION=us-west-2 AWS_PROFILE=vindicara cdk synth`
- [ ] Review synth output for any remaining `335741630084` strings (sanity).
- [ ] `AWS_PROFILE=vindicara cdk deploy VindicaraData VindicaraEvents VindicaraAPI` (CDK will deploy in dependency order automatically).
- [ ] Capture new API Gateway endpoint ID and Lambda ARN from outputs.
- [ ] Smoke test: `curl -sI https://<new-api-id>.execute-api.us-west-2.amazonaws.com/health` should return 200 or expected status.

### Step 3 — Frontend infra in new account
- [ ] Request ACM cert in `us-east-1` (note: us-east-1, not us-west-2; CloudFront requires it) for `vindicara.io` and `www.vindicara.io`. Use DNS validation.
- [ ] Create CNAME validation records in the active Route 53 zone (still old account at this point if we picked option b, or new zone if option a).
- [ ] Wait for cert ISSUED.
- [ ] Create new S3 bucket `vindicara-site-399827112476` in `us-west-2`, configure for static website hosting, block-all-public-access set, S3-managed encryption.
- [ ] `cd site && npm ci && npm run build`
- [ ] `AWS_PROFILE=vindicara aws s3 sync site/build/ s3://vindicara-site-399827112476/ --delete`
- [ ] Create new CloudFront distribution: aliases `vindicara.io`/`www.vindicara.io`, origins (1) new S3 site bucket, (2) new API Gateway URL with `/dashboard*` behavior; cert from previous step. Origin Access Control for S3.
- [ ] Wait for distribution status `Deployed`.
- [ ] Test direct hit: `curl -sI https://<new-cf-id>.cloudfront.net` returns 200 with site content.

### Step 4 — DNS cutover (option (a) zone migrate, confirmed)

**Current TTLs (read from zone `Z0749902KU2J4ZS2UQ4Z` on 2026-04-29):**
- `vindicara.io` NS: 172800s (48h) ← the limiting factor for the registrar NS swap
- `vindicara.io` SOA: 900s
- MX, TXT, DMARC, DKIM, ACM-validation CNAME: 300s
- A-alias records (`vindicara.io`, `www.vindicara.io`): no TTL (alias records inherit CloudFront-edge propagation)

**Pre-cutover TTL lowering (do this BEFORE the registrar NS swap):**
- [ ] In old zone, lower NS record TTL from 172800s to 300s. **Then wait the FULL OLD TTL of 172800s (48 hours).** Do not skip this. The full 48h wait ensures any resolver that cached the NS RRset under the old TTL has expired its cache before the registrar swap. Skipping this means a worst-case resolver could route to the dead old zone for up to 48h after the swap.
- [ ] In old zone, lower MX/TXT/DMARC/DKIM/CNAME TTLs from 300s to 60s. Wait the full old TTL of 300s.
- [ ] (No action needed for A-alias records: they have no TTL.)

**Zone migrate (after the 48h NS-TTL wait completes):**
- [ ] Export records from old zone:
  ```
  aws route53 list-resource-record-sets --profile default --hosted-zone-id Z0749902KU2J4ZS2UQ4Z > zone-export.json
  ```
- [ ] Create new zone in new account:
  ```
  aws route53 create-hosted-zone --profile vindicara --name vindicara.io --caller-reference vindicara-migrate-$(date +%s)
  ```
- [ ] Capture the new zone ID and the new NS set from the response.
- [ ] Re-create non-NS, non-SOA records in the new zone, with alias A records pointing to the **new** CloudFront distribution from Step 3. Use ChangeResourceRecordSets with `--change-batch` JSON.
- [ ] Verify the new zone resolves correctly by querying its NS servers directly:
  ```
  dig @<new-ns-1> vindicara.io A
  dig @<new-ns-1> www.vindicara.io A
  ```
- [ ] Confirm new CloudFront distribution alias responds 200.

**Registrar NS swap (Porkbun):**
- [ ] At Porkbun control panel for `vindicara.io`, replace the NS records with the new zone's NS set.
- [ ] Allow propagation. Most public resolvers respect the lowered 300s TTL; the theoretical worst case is bounded by the time we waited above plus DNS resolver cache behavior.

**Verify after propagation:**
- [ ] `dig vindicara.io NS` returns the new NS set from a fresh resolver (e.g., `dig @1.1.1.1 vindicara.io NS`).
- [ ] `curl -sI https://vindicara.io` returns 200 with content from the new CloudFront distribution.
- [ ] `curl -sI https://www.vindicara.io` returns 200.

**Rollback:** at Porkbun, revert NS records to the old zone's NS set: `ns-1525.awsdns-62.org`, `ns-501.awsdns-62.com`, `ns-1618.awsdns-10.co.uk`, `ns-655.awsdns-17.net`. The old zone is still alive and serves the old CloudFront. Recovery time bounded by the (now lowered) 300s TTL plus resolver caches.

### Step 5 — Cutover validation (24-48h soak)
- [ ] CloudWatch alarms in new account on Lambda errors, API Gateway 5xx, CloudFront 5xx.
- [ ] Site fetch returns 200 with `last-modified` matching the new sync.
- [ ] `/dashboard*` reaches new Lambda (test a known dashboard endpoint).
- [ ] GitHub Actions `deploy-site.yml` runs against new account (use OIDC role or rotated keys).

### Step 6 — Decommission old account
- [ ] `cdk destroy --profile default VindicaraAPI` (deletes Lambda + API GW; tables retained because of `RemovalPolicy.RETAIN`).
- [ ] `cdk destroy --profile default VindicaraEvents`.
- [ ] `cdk destroy --profile default VindicaraData` (will fail to delete the retained DDB tables and S3 bucket; that is expected; clean up manually).
- [ ] `aws dynamodb delete-table --profile default --table-name vindicara-policies` (and `evaluations`, `api-keys`) — only after confirming empty.
- [ ] `aws s3 rb --profile default s3://vindicara-audit-335741630084 --force` (empty audit bucket).
- [ ] `aws s3 rb --profile default s3://vindicara-site-335741630084 --force` (after final traffic check).
- [ ] Disable then delete CloudFront `E2EIWI2GTEUFWW`.
- [ ] Delete ACM certs `5688e99b...` and `57cf6783...`.
- [ ] If option (a): delete old Route 53 zone `Z0749902KU2J4ZS2UQ4Z`.
- [ ] Rotate / disable IAM user `Kev-Dev` access keys.
- [ ] Save final billing report from old account before final close.

---

## 5. Rollback Plan

| Phase | Failure mode | Rollback |
|---|---|---|
| 1 (code changes) | PR breaks tests | Revert PR, no infra impact |
| 2 (CDK deploy in new account) | Synth fails / deploy errors | `cdk destroy` the partially-deployed stacks; old account untouched and still serving traffic |
| 3 (frontend infra) | ACM cert validation fails / CloudFront origin misconfigured | Delete the new CloudFront distribution and S3 bucket; old account untouched |
| 4 (DNS cutover) | New endpoints return errors after cutover | At Porkbun (option a) revert NS records to `ns-1525.awsdns-62.org`, `ns-501.awsdns-62.com`, `ns-1618.awsdns-10.co.uk`, `ns-655.awsdns-17.net` (the old zone NS set). At Route 53 (option b) revert alias target back to old CloudFront. With 60s TTL, recovery is under five minutes. |
| 5 (validation soak) | Errors observed | Same as phase 4 rollback. Investigate root cause before retry. |
| 6 (decommission) | Premature deletion | Recovery is significantly harder once an S3 bucket is deleted (the name is reusable but globally-unique reservations release after a delay). Keep retained tables and buckets paused (not deleted) for at least 14 days post-cutover before final deletion. |

The single-most-important rollback rule: **do not run any step in phase 6 until phase 5 has run cleanly for 24-48h.**

---

## 6. Open Questions (require user answer before Phase 2)

1. **What is the trigger for the move?** Is this Vindicara-Inc legal-entity ownership cleanup, or AWS Activate credits at the new account, or both? Affects whether we should claim old credits before deletion.
2. **Route 53 zone:** (a) migrate the zone to the new account (cleaner, more work), or (b) leave it in the old account and only repoint alias targets (simpler short-term, leaves a dependency on the old account)? Recommendation: (a), since the entire point of the move is to leave the old account.
3. **Site infra under CDK?** Currently S3 + CloudFront + ACM are manually managed. Migration is a clean moment to bring them into a new `SiteStack`. Estimate: ~120 lines of CDK. Recommendation: bring into CDK.
4. **GitHub Actions auth:** rotate IAM access keys, or switch to OIDC (`aws-actions/configure-aws-credentials@v4` with `role-to-assume`)? Recommendation: OIDC, since the new account is a fresh start and access keys are an audit liability.
5. **Lambda build:** `lambda_package/` does not exist in the tree. What is the canonical build command? If there isn't one, this needs to be written before Phase 2.
6. **Bedrock:** the new account has Claude available in us-west-2. Confirm we want this region partly because of that (AIR Cloud Phase 1 ingestion may use it). If not, us-east-1 in the new account would simplify the CloudFront cert geography (cert can stay in same region as workload). Recommendation: keep us-west-2 if Bedrock is in the AIR Cloud roadmap; switch to us-east-1 otherwise.
7. **PyPI package owner email:** is `eng@vindicara.io` already the project owner on PyPI, or is it still `kev.minn009@gmail.com` / `kevin@sltrdigital.com`? Out of scope for AWS migration but worth fixing in the same window.
8. **Confirm assumption:** no live paying customers, no third party watching for the API Gateway URL `d1xzz26fz4.execute-api.us-east-1.amazonaws.com`? The URL is referenced in CloudFront only, so a clean cutover is possible, but confirm before starting.
9. **Old-account other resources:** `Kev-Dev` user shares the old account with Luminetic, MemoryAisle, ThemisPrism, Pass1099, DriftLab, etc. None of those were touched in this discovery. Confirm no shared IAM roles, KMS keys, or VPCs that Vindicara depends on but that we did not enumerate.
10. **VindicaraData rollback state:** the old stack is `UPDATE_ROLLBACK_COMPLETE`. Since we are deleting it, no fix needed. But it may have been the symptom of a prior issue (the audit-bucket-rename attempt?) worth understanding before redeploying the same stack to the new account.

---

**End of Phase 1.** Awaiting user review before Phase 2.
