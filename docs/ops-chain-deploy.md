# Vindicara ops chain: deploy runbook

This is Kevin's deploy procedure for `OpsChainStack`. Read end-to-end before running anything; the steps assume you are on branch `ops/dogfood-air-chain` against the Vindicara C-Corp account `399827112476` in us-west-2.

## Pre-flight: add the alarm email alias

`OpsChainStack` subscribes `alerts@vindicara.io` to the alarm SNS topic. If that alias does not yet exist on Porkbun forwarding, add it before deploy:

1. Log in to Porkbun.
2. Email Forwarding for `vindicara.io`: add `alerts → kev.minn009@gmail.com` (or whatever distribution target is preferred).
3. After CDK deploy, AWS sends a confirmation email to `alerts@vindicara.io`. Follow the link to confirm the SNS subscription. Until confirmed, no alarms are delivered.

## Pre-flight: tests + lint

```bash
cd /Users/KMiI/Desktop/vindicara
source .venv-air/bin/activate

# 1. Run the offline smoke test. Must print "[e2e] PASS".
python scripts/e2e_ops_chain.py

# 2. All ops + integration tests pass.
python -m pytest tests/unit/ops/ tests/integration/api/

# 3. Lint + types are clean on the new surface.
ruff check src/vindicara/ops/ src/vindicara/api/middleware/ops_chain.py src/vindicara/infra/stacks/ops_chain_stack.py
mypy --strict src/vindicara/ops/ src/vindicara/api/middleware/ops_chain.py

# 4. Confirm the AWS account + region you're about to deploy into.
aws sts get-caller-identity --profile vindicara | grep Arn
# expect: arn:aws:iam::399827112476:user/vindicara-air

aws configure get region --profile vindicara
# expect: us-west-2
```

If any of these fail, stop and fix before deploying. The chain is permanent; a buggy deploy that anchors garbage to Rekor is permanent.

## Stage 1: rebuild lambda_package

```bash
cd /Users/KMiI/Desktop/vindicara
./scripts/build-lambda.sh
# Verify it includes the new ops module
ls lambda_package/vindicara/ops/
# expect: __init__.py, anchorer.py, ddb_transport.py, publisher.py, recorder.py, redaction.py, schema.py
```

## Stage 2: synth the new stack alone

```bash
VINDICARA_AWS_ACCOUNT_ID=399827112476 cdk synth VindicaraOpsChain
```

Inspect the output. Confirm:
- `OpsChainTable` is `vindicara-ops-chain` with `chain_id` partition + `ord` sort, PITR on, RETAIN policy.
- `OpsChainBucket` is `vindicara-ops-chain-public-399827112476` with public-read on the `ops-chain/*` prefix only.
- Two Lambdas (`vindicara-ops-anchorer`, `vindicara-ops-publisher`) on EventBridge schedules at 1-minute cadence.

If anything looks off, stop and fix `src/vindicara/infra/stacks/ops_chain_stack.py`.

## Stage 3: deploy the new stack only

```bash
AWS_PROFILE=vindicara VINDICARA_AWS_ACCOUNT_ID=399827112476 cdk deploy VindicaraOpsChain --require-approval broadening
```

The flag `--require-approval broadening` makes CDK confirm before any IAM-broadening change. Read the diff carefully. Type `y` only after you have verified that:
- No stack other than `VindicaraOpsChain` is being modified.
- The bucket policy lists exactly one `s3:GetObject` action on `ops-chain/*`, no other actions.
- The Lambda IAM roles only grant DDB read/write to `vindicara-ops-chain` and S3 PutObject to the public bucket.

Wait for `VindicaraOpsChain: deploy completed`.

## Stage 4: deploy VindicaraAPI to wire the table grant

The api function needs `grant_write_data` against the new ops chain table; `cdk deploy` without filtering touches everything. Re-deploy explicitly:

```bash
AWS_PROFILE=vindicara VINDICARA_AWS_ACCOUNT_ID=399827112476 cdk deploy VindicaraAPI --require-approval broadening
```

Confirm the diff is just an IAM policy addition + an `add_environment` for `VINDICARA_OPS_CHAIN_TABLE`. Type `y`.

## Stage 5: populate the anchoring key secret

`OpsChainStack` declares an empty Secrets Manager secret named `vindicara/ops-chain/anchoring-key` and grants read access to the anchorer Lambda. The anchorer fetches the secret value at invocation time and stages it as `AIRSDK_ANCHORING_KEY`. The secret itself is operator-populated, so the PEM never lives in CloudFormation.

```bash
# Generate an ECDSA P-256 PEM locally
python -c "
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat
priv = ec.generate_private_key(ec.SECP256R1())
print(priv.private_bytes(encoding=Encoding.PEM, format=PrivateFormat.PKCS8, encryption_algorithm=NoEncryption()).decode())
" > /tmp/vindicara-ops-anchoring-key.pem
chmod 600 /tmp/vindicara-ops-anchoring-key.pem

# Populate the CDK-declared secret. Use put-secret-value (not create-secret)
# because OpsChainStack already created the resource shell.
aws secretsmanager put-secret-value \
    --profile vindicara \
    --region us-west-2 \
    --secret-id vindicara/ops-chain/anchoring-key \
    --secret-string "$(cat /tmp/vindicara-ops-anchoring-key.pem)"

# Save the public key too: print it to a file the operator commits to docs/
# so anyone can verify chain signatures offline. PEM only, never the private key.
python -c "
import sys
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, load_pem_private_key
priv = load_pem_private_key(open('/tmp/vindicara-ops-anchoring-key.pem','rb').read(), password=None)
print(priv.public_key().public_bytes(encoding=Encoding.PEM, format=PublicFormat.SubjectPublicKeyInfo).decode())
" > docs/ops-chain-public-key.pem

# Delete the local private copy
shred -u /tmp/vindicara-ops-anchoring-key.pem
```

## Stage 6: drive synthetic traffic

After Stage 4, the api Lambda's middleware is live; every request to the production API now writes to DDB. Drive a few:

```bash
curl -H "X-Vindicara-Key: vnd_demo" https://<api-endpoint>/v1/policies
curl -H "X-Vindicara-Key: vnd_demo" https://<api-endpoint>/v1/health
# (note /health is in PUBLIC_PATHS so it skips the ops chain by design)

# Confirm DDB has rows
aws dynamodb scan --profile vindicara --region us-west-2 --table-name vindicara-ops-chain --max-items 5
```

Wait 60-90 seconds. Then:

```bash
# Confirm the anchorer ran and anchored chains
aws logs tail --profile vindicara --region us-west-2 /aws/lambda/vindicara-ops-anchorer --since 5m

# Confirm the publisher ran
aws logs tail --profile vindicara --region us-west-2 /aws/lambda/vindicara-ops-publisher --since 5m

# Hit the public manifest
curl https://vindicara-ops-chain-public-399827112476.s3.us-west-2.amazonaws.com/ops-chain/manifest.json

# Pull a published chain
curl https://vindicara-ops-chain-public-399827112476.s3.us-west-2.amazonaws.com/ops-chain/<chain-id>.jsonl
```

## Stage 7: verify with public tooling

```bash
pip install projectair  # if not already installed
air verify-public https://vindicara-ops-chain-public-399827112476.s3.us-west-2.amazonaws.com/ops-chain/<chain-id>.jsonl
```

This must succeed. If it fails:
- Check that the chain JSONL on S3 is well-formed (one JSON object per line).
- Check that the `rekor_log_index` in the chain points at a real public Rekor entry by visiting `https://search.sigstore.dev/?logIndex=<index>`.

## Stage 8: open the soak window

Drive low-volume synthetic traffic through the API for 48 hours (e.g., a curl-loop running every 5 minutes from a separate machine). Watch:
- CloudWatch alarms (Lambda errors, API GW 5xx) stay green.
- The manifest's latest log index increments at least every 90 seconds.
- No `vindicara.ops.anchorer.anchor_failed` or `vindicara.ops.publisher.publish_failed` lines accumulate beyond a transient blip.

If anything turns red, the launch slips. Per `feedback_fail_pre_spotlight.md`, slip is the default not the exception.

## Stage 9: rollback if needed

Worst case: the chain is corrupt or the anchorer has anchored garbage to Rekor. The Rekor entries cannot be deleted (transparency-log invariant), but you can stop emitting new ones cleanly:

```bash
# Stop both crons
aws events disable-rule --profile vindicara --region us-west-2 --name vindicara-ops-anchorer-schedule
aws events disable-rule --profile vindicara --region us-west-2 --name vindicara-ops-publisher-schedule

# Make the api middleware a no-op by clearing the env var
aws lambda update-function-configuration \
    --profile vindicara \
    --region us-west-2 \
    --function-name vindicara-api \
    --environment "Variables={VINDICARA_STAGE=prod,VINDICARA_LOG_LEVEL=INFO,...}"  # without VINDICARA_OPS_CHAIN_TABLE
```

Investigate, fix, redeploy, re-enable rules. The Rekor entries from the failed run remain public; they are recoverable narrative ("we tried; here is what failed; here is the fix"), not a brand crisis.

## Open follow-ups (post-deploy)

1. Wire the dashboard auth handlers to emit `auth_event` records (currently every dashboard request only gets the generic `api_request` envelope).
2. Build the operator CLI (key revoke / DSAR fulfill / redaction policy change) with Auth0 step-up gating per Layer 3 containment.
3. Add a stale-chain alarm on the anchorer Lambda. Currently the only signal is the manifest going stale.
