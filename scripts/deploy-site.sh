#!/usr/bin/env bash
# Build and deploy the marketing site (site/) to S3 + CloudFront.
# Requires: aws CLI authenticated with permissions for the bucket and distribution.
#
# Required env vars (no defaults; fails loud if missing):
#   VINDICARA_SITE_BUCKET   S3 bucket name (e.g. vindicara-site-399827112476)
#   VINDICARA_CF_DIST_ID    CloudFront distribution ID
#   AWS_PROFILE             AWS profile (e.g. vindicara)

set -euo pipefail

: "${VINDICARA_SITE_BUCKET:?VINDICARA_SITE_BUCKET must be set (e.g. vindicara-site-399827112476)}"
: "${VINDICARA_CF_DIST_ID:?VINDICARA_CF_DIST_ID must be set (CloudFront distribution ID)}"
: "${AWS_PROFILE:?AWS_PROFILE must be set (e.g. vindicara)}"

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SITE_DIR="$REPO_ROOT/site"
BUILD_DIR="$SITE_DIR/build"

echo "==> Building site"
(cd "$SITE_DIR" && npm run build)

if [[ ! -d "$BUILD_DIR" ]]; then
  echo "build directory not found: $BUILD_DIR" >&2
  exit 1
fi

echo "==> Syncing to s3://$VINDICARA_SITE_BUCKET (profile=$AWS_PROFILE)"
aws s3 sync "$BUILD_DIR/" "s3://$VINDICARA_SITE_BUCKET/" --delete --profile "$AWS_PROFILE"

echo "==> Invalidating CloudFront $VINDICARA_CF_DIST_ID"
INVALIDATION_ID=$(
  aws cloudfront create-invalidation \
    --profile "$AWS_PROFILE" \
    --distribution-id "$VINDICARA_CF_DIST_ID" \
    --paths "/*" \
    --query 'Invalidation.Id' \
    --output text
)

echo "==> Invalidation queued: $INVALIDATION_ID"
echo "==> Deploy complete. https://vindicara.io"
