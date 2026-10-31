#!/usr/bin/env bash
set -Eeuo pipefail

# Run this script from any directory; seine and the bridge are expected
# to be alongside this script unless overridden below.
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

SEINE_BIN="${SEINE_BIN:-$SCRIPT_DIR/seine}"
BRIDGE_SCRIPT="${BRIDGE_SCRIPT:-}"
RELAY_URL="${RELAY_URL:-wss://late-surf-18bd.codenamesamael.workers.dev/bntpool}"
POOL_HOST="${POOL_HOST:-bntpool.com}"
POOL_PORT="${POOL_PORT:-3333}"
LOCAL_HOST="${LOCAL_HOST:-127.0.0.1}"
LOCAL_PORT="${LOCAL_PORT:-33333}"
WALLET_ADDRESS="${WALLET_ADDRESS:-7eseCPTmrS9bmYs4oonUq3WjMxTW8nsY3ueyYCBCT6BTWiWAxHGKmMEaGuUexXXxzYUWt95NmnxZMvQC5GLqcDEzQJEWm}"
BRIDGE_LOG="${BRIDGE_LOG:-$SCRIPT_DIR/cf-relay-bridge.log}"

# Accept either the uploaded filename or the usual renamed filename.
if [[ -z "$BRIDGE_SCRIPT" ]]; then
  if [[ -f "$SCRIPT_DIR/cf-relay-bridge(1).py" ]]; then
    BRIDGE_SCRIPT="$SCRIPT_DIR/cf-relay-bridge(1).py"
  elif [[ -f "$SCRIPT_DIR/cf_relay_bridge.py" ]]; then
    BRIDGE_SCRIPT="$SCRIPT_DIR/cf_relay_bridge.py"
  else
    echo "ERROR: Cannot find cf-relay-bridge(1).py or cf_relay_bridge.py beside this script." >&2
    echo "Set BRIDGE_SCRIPT=/path/to/your/bridge.py and run again." >&2
    exit 1
  fi
fi

if [[ ! -x "$SEINE_BIN" ]]; then
  echo "ERROR: seine binary not found or not executable: $SEINE_BIN" >&2
  echo "Put this script beside ./seine, or set SEINE_BIN=/path/to/seine." >&2
  exit 1
fi

if ! command -v python3 >/dev/null 2>&1; then
  echo "ERROR: python3 is required for the Cloudflare relay bridge." >&2
  exit 1
fi

if [[ ! -f "$BRIDGE_SCRIPT" ]]; then
  echo "ERROR: bridge script not found: $BRIDGE_SCRIPT" >&2
  exit 1
fi

BRIDGE_PID=""
MINER_PID=""

cleanup() {
  # Prevent recursive trap execution while cleaning up.
  trap - EXIT INT TERM

  if [[ -n "$MINER_PID" ]] && kill -0 "$MINER_PID" 2>/dev/null; then
    kill "$MINER_PID" 2>/dev/null || true
    wait "$MINER_PID" 2>/dev/null || true
  fi

  if [[ -n "$BRIDGE_PID" ]] && kill -0 "$BRIDGE_PID" 2>/dev/null; then
    echo "Stopping Cloudflare relay bridge (PID $BRIDGE_PID)..."
    kill "$BRIDGE_PID" 2>/dev/null || true
    wait "$BRIDGE_PID" 2>/dev/null || true
  fi
}

trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

printf '%s\n' "Starting Cloudflare relay bridge..."
printf 'Relay:  %s -> %s:%s\n' "$RELAY_URL" "$POOL_HOST" "$POOL_PORT"
printf 'Local:  %s:%s\n' "$LOCAL_HOST" "$LOCAL_PORT"
printf 'Log:    %s\n' "$BRIDGE_LOG"

python3 "$BRIDGE_SCRIPT" \
  --listen "$LOCAL_HOST:$LOCAL_PORT" \
  --relay "$RELAY_URL" \
  --target "$POOL_HOST:$POOL_PORT" \
  >"$BRIDGE_LOG" 2>&1 &
BRIDGE_PID=$!

# Give the bridge a moment to bind its local port; detect an early startup failure.
sleep 1
if ! kill -0 "$BRIDGE_PID" 2>/dev/null; then
  echo "ERROR: relay bridge exited during startup. Recent log output:" >&2
  tail -n 40 "$BRIDGE_LOG" >&2 || true
  exit 1
fi

echo "Starting Seine miner through the local relay..."
"$SEINE_BIN" \
  --pool-url "stratum+tcp://$LOCAL_HOST:$LOCAL_PORT" \
  --address "$WALLET_ADDRESS" &
MINER_PID=$!

# Preserve the miner's exit status; EXIT trap will stop the bridge.
set +e
wait "$MINER_PID"
MINER_STATUS=$?
set -e
exit "$MINER_STATUS"
