#!/usr/bin/env bash
# Build and deploy the marketing site (site/) to S3 + CloudFront.
# Requires: aws CLI authenticated with permissions for the bucket and distribution.
#
# Overrides:
#   VINDICARA_SITE_BUCKET   (default: vindicara-site-335741630084)
#   VINDICARA_CF_DIST_ID    (default: E2EIWI2GTEUFWW)

set -euo pipefail

BUCKET="${VINDICARA_SITE_BUCKET:-vindicara-site-335741630084}"
DIST_ID="${VINDICARA_CF_DIST_ID:-E2EIWI2GTEUFWW}"

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SITE_DIR="$REPO_ROOT/site"
BUILD_DIR="$SITE_DIR/build"

echo "==> Building site"
(cd "$SITE_DIR" && npm run build)

if [[ ! -d "$BUILD_DIR" ]]; then
  echo "build directory not found: $BUILD_DIR" >&2
  exit 1
fi

echo "==> Syncing to s3://$BUCKET"
aws s3 sync "$BUILD_DIR/" "s3://$BUCKET/" --delete

echo "==> Invalidating CloudFront $DIST_ID"
INVALIDATION_ID=$(
  aws cloudfront create-invalidation \
    --distribution-id "$DIST_ID" \
    --paths "/*" \
    --query 'Invalidation.Id' \
    --output text
)

echo "==> Invalidation queued: $INVALIDATION_ID"
echo "==> Deploy complete. https://vindicara.io"
