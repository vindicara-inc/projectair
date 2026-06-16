# AIR Cloud deploy + operator runbook

How to deploy the hosted AIR Cloud ingest service and provision tenant workspaces.

Stack: `src/vindicara/infra/stacks/air_cloud_stack.py` (`AirCloudStack`). It creates three DynamoDB tables, the API Lambda + HTTP API Gateway, CloudWatch alarms, and the W3.10 admin-token secret.

## Deploy

From the repo root, with the target account's profile and region:

```bash
source .venv-air/bin/activate

# Gate the change first.
ruff check src/vindicara/cloud && mypy --strict src/vindicara/cloud
pytest tests/unit/cloud tests/integration/cloud -q

# Repackage so the Lambda ships the current factory.py / cloud code.
./scripts/build-lambda.sh

VINDICARA_AWS_ACCOUNT_ID=399827112476 AWS_PROFILE=vindicara \
  cdk deploy AirCloudStack
```

The `build-lambda.sh` step is mandatory before any cloud deploy: the admin-token resolution and route logic live in `vindicara.cloud`, which rides inside the `lambda_package/` asset. Deploying without rebuilding ships stale code.

## Workspace creation is operator-only (W3.10)

`POST /v1/workspaces` provisions a tenant and is gated by a deploy-time operator admin token, not by a workspace role. A brand-new tenant has no API key yet, so role-based auth cannot gate it; the operator holds the credential instead.

How the token is resolved at runtime (`vindicara.cloud.factory._resolve_admin_token`), in precedence order:

1. explicit `admin_token` kwarg to `create_air_cloud_app` (tests/local);
2. `AIR_CLOUD_ADMIN_TOKEN` env var;
3. the Secrets Manager secret named by `AIR_CLOUD_ADMIN_TOKEN_SECRET_ARN`.

If none resolve, workspace creation is disabled and returns 503. It is never left open in a half-configured state.

In the deployed stack, CDK auto-generates the secret `air-cloud-admin-token` (48 chars, no punctuation), passes its ARN to the Lambda, and grants the Lambda read access to that secret only. Nobody types or commits the token, and it is absent from the CloudFormation template.

## Fetch the admin token

```bash
aws secretsmanager get-secret-value \
  --secret-id air-cloud-admin-token \
  --query SecretString --output text \
  --profile vindicara --region us-west-2
```

## Provision a tenant workspace

```bash
curl -X POST https://<api-id>.execute-api.us-west-2.amazonaws.com/v1/workspaces \
  -H "X-Admin-Token: <token-from-above>" \
  -H "Content-Type: application/json" \
  -d '{"workspace_id":"design-partner-1","name":"Partner One","owner_email":"ops@partner.io"}'
```

The response returns the workspace's bootstrap API key exactly once. Store it; it cannot be retrieved later. Hand it to the design partner out of band. From then on they authenticate with `X-API-Key` and manage their own keys and members; their key cannot create additional workspaces.

## Rotate the admin token

Rotating only affects who can create new workspaces; it does not touch existing tenants or their keys.

```bash
# Generate a new value and store it.
aws secretsmanager put-secret-value \
  --secret-id air-cloud-admin-token \
  --secret-string "$(openssl rand -hex 24)" \
  --profile vindicara --region us-west-2
```

The Lambda picks up the new value on its next cold start (it reads the secret at app construction). Force a refresh by updating the function configuration or redeploying if you need it immediately.

## Self-serve signup (future)

When self-serve signup lands, the OIDC login path (`vindicara.cloud.sso`) mints its own provisioning credential and reuses the same store-backed creation logic. `require_admin` stays as the operator escape hatch for out-of-band provisioning. No schema change is required to add it.
