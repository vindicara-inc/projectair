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
DASH_DIR="$REPO_ROOT/packages/air-dashboard"

echo "==> Building site"
(cd "$SITE_DIR" && npm run build)

if [[ ! -d "$BUILD_DIR" ]]; then
  echo "build directory not found: $BUILD_DIR" >&2
  exit 1
fi

echo "==> Building AIR Cloud dashboard"
(cd "$DASH_DIR" && \
  VITE_AUTH0_DOMAIN=dev-kilt2vkudvbu75ny.us.auth0.com \
  VITE_AUTH0_CLIENT_ID=GszbWqSkD65eUjv7FrRWYO4IkmGWdd4y \
  VITE_AIR_CLOUD_URL=https://cloud.vindicara.io \
  npm run build)

if [[ ! -d "$DASH_DIR/build" ]]; then
  echo "dashboard build directory not found: $DASH_DIR/build" >&2
  exit 1
fi

echo "==> Merging dashboard into site at /dashboard/"
cp -r "$DASH_DIR/build/" "$BUILD_DIR/dashboard/"

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
