#!/usr/bin/env bash
# 60-second proof of the self-hosted / air-gapped AIR Enterprise unit.
#
# Proves three things a regulated buyer cares about:
#   1. GATE       no valid license  -> container refuses to start (exit 1).
#   2. BOOT       valid Enterprise license -> it serves (/health 200).
#   3. DURABILITY POST a signed capsule -> restart the container -> GET it back.
#
# Requires: docker, and the vendor signing key at ~/.airsdk-vendor (operator only).
# Run from the repo root:  bash deploy/demo_selfhosted.sh
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

IMAGE="air-enterprise:demo"
NAME="air-enterprise-demo"
VOLUME="air-demo-data"
PORT="8080"
ADMIN_TOKEN="demo-admin-token"
WORK="$(mktemp -d)"
LICENSE="$WORK/license.json"
PY="${PYTHON:-python3}"

cleanup() {
  docker rm -f "$NAME" >/dev/null 2>&1 || true
  docker volume rm "$VOLUME" >/dev/null 2>&1 || true
  rm -rf "$WORK"
}
trap cleanup EXIT

step() { printf '\n\033[1m== %s ==\033[0m\n' "$1"; }

step "Build the image"
docker build -f deploy/Dockerfile -t "$IMAGE" .

step "1. GATE: run with NO license (must refuse, exit non-zero)"
set +e
docker run --rm --name "${NAME}-nogate" "$IMAGE"
CODE=$?
set -e
if [ "$CODE" -eq 0 ]; then
  echo "FAIL: container started without a license"; exit 1
fi
echo "PASS: refused to start without a license (exit $CODE)"

step "Mint a demo Enterprise license (operator, offline)"
"$PY" deploy/make_demo_license.py enterprise "$LICENSE"

step "2. BOOT: run with the Enterprise license + durable volume"
docker run -d --name "$NAME" -p "$PORT:8080" \
  -e "AIR_CLOUD_ADMIN_TOKEN=$ADMIN_TOKEN" \
  -v "$LICENSE:/etc/airsdk/license.json:ro" \
  -v "$VOLUME:/var/lib/airsdk" \
  "$IMAGE"

echo -n "waiting for /health"
for _ in $(seq 1 30); do
  if curl -sf "http://localhost:$PORT/health" >/dev/null 2>&1; then break; fi
  echo -n "."; sleep 1
done
echo
curl -sf "http://localhost:$PORT/health" && echo "  <- PASS: serving"

step "Bootstrap a workspace (operator admin token)"
WS_JSON="$(curl -sf -X POST "http://localhost:$PORT/v1/workspaces" \
  -H "X-Admin-Token: $ADMIN_TOKEN" -H "Content-Type: application/json" \
  -d '{"workspace_id":"ws_buyer","name":"Regulated Buyer","owner_email":"buyer@example.com"}')"
API_KEY="$("$PY" -c "import sys,json;print(json.load(sys.stdin)['bootstrap_api_key']['key'])" <<<"$WS_JSON")"
echo "issued bootstrap API key: ${API_KEY:0:12}..."

step "3. DURABILITY: POST a signed capsule, then restart the container"
"$PY" deploy/make_demo_capsule.py > "$WORK/capsule.json"
curl -sf -X POST "http://localhost:$PORT/v1/capsules" \
  -H "X-API-Key: $API_KEY" -H "Content-Type: application/json" \
  --data-binary "@$WORK/capsule.json" >/dev/null
BEFORE="$(curl -sf "http://localhost:$PORT/v1/capsules" -H "X-API-Key: $API_KEY" | "$PY" -c "import sys,json;print(json.load(sys.stdin)['count'])")"
echo "capsules before restart: $BEFORE"

docker restart "$NAME" >/dev/null
echo -n "waiting for /health after restart"
for _ in $(seq 1 30); do
  if curl -sf "http://localhost:$PORT/health" >/dev/null 2>&1; then break; fi
  echo -n "."; sleep 1
done
echo

AFTER="$(curl -sf "http://localhost:$PORT/v1/capsules" -H "X-API-Key: $API_KEY" | "$PY" -c "import sys,json;print(json.load(sys.stdin)['count'])")"
echo "capsules after restart:  $AFTER"

if [ "$BEFORE" = "1" ] && [ "$AFTER" = "1" ]; then
  echo -e "\n\033[1;32mPASS: the forensic chain, workspace, and API key survived the restart.\033[0m"
else
  echo -e "\n\033[1;31mFAIL: expected 1 capsule before and after restart (got $BEFORE / $AFTER).\033[0m"; exit 1
fi
