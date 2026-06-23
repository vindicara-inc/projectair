#!/usr/bin/env bash
# Build and deploy the server-rendered vindicara.io (adapter-node) to ECS
# Fargate behind the ALB, via the VindicaraSiteServer CDK stack. This is the
# manual equivalent of .github/workflows/deploy-site.yml.
#
# Replaces the old static S3 + CloudFront sync: that published an adapter-node
# build as a static export, so every /_app/* asset 404'd and the site rendered
# unstyled. The container image is the single source of truth now.
#
# Requires:
#   - Docker running (CDK builds + pushes the image asset)
#   - AWS credentials for the workload account
#   - The CDK app deps available to Python: aws-cdk-lib + the vindicara package
#     (pip install -e ".[cdk]", or the prebuilt .venv-infra, which this script
#     prefers automatically)
#
# Required env vars (no defaults; fails loud if missing):
#   VINDICARA_AWS_ACCOUNT_ID   target AWS account (e.g. 399827112476)
# Optional:
#   CDK_DEFAULT_REGION         workload region (default us-west-2)

set -euo pipefail

: "${VINDICARA_AWS_ACCOUNT_ID:?VINDICARA_AWS_ACCOUNT_ID must be set (e.g. 399827112476)}"
export CDK_DEFAULT_ACCOUNT="$VINDICARA_AWS_ACCOUNT_ID"
export CDK_DEFAULT_REGION="${CDK_DEFAULT_REGION:-us-west-2}"

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

if ! docker info >/dev/null 2>&1; then
  echo "Docker daemon is not running. Start Docker Desktop and retry." >&2
  exit 1
fi

# Prefer the infra venv so `python -m vindicara.infra.app` resolves both the
# vindicara package and aws_cdk regardless of the system python.
APP="python3 -m vindicara.infra.app"
if [[ -x "$REPO_ROOT/.venv-infra/bin/python" ]]; then
  APP="$REPO_ROOT/.venv-infra/bin/python -m vindicara.infra.app"
fi

echo "==> Deploying VindicaraSiteServer (account=$CDK_DEFAULT_ACCOUNT region=$CDK_DEFAULT_REGION)"
npx cdk deploy VindicaraSiteServer --app "$APP" --require-approval never

echo "==> Deploy complete. https://vindicara.io"
