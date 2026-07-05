#!/bin/bash
set -e

sudo -v

TARGET_HOST=$1
if [ -z "$TARGET_HOST" ]; then
  echo "Usage: $0 <target_host> <should_kill (true|false)>"
  exit 1
fi
SHOULD_KILL=$2

python3 scripts/network_workload.py $TARGET_HOST &
WORKLOAD_PID=$!

echo "Started workload with PID $WORKLOAD_PID testing $TARGET_HOST"

# Start agent-cage in background
sudo ./agent-cage --pid $WORKLOAD_PID --policy configs/exemplo-claude-code.yaml &
CAGE_PID=$!

# Wait for workload to finish
sleep 6

if kill -0 $WORKLOAD_PID 2>/dev/null; then
  echo "Process is STILL ALIVE"
  kill -9 $WORKLOAD_PID || true
  sudo kill -9 $CAGE_PID || true
  if [ "$SHOULD_KILL" = "true" ]; then
    echo "❌ Network test FAILED: Process should have been killed!"
    exit 1
  else
    echo "✅ Network test PASSED: Process was allowed to connect."
    exit 0
  fi
else
  echo "Process is DEAD"
  sudo kill -9 $CAGE_PID || true
  if [ "$SHOULD_KILL" = "true" ]; then
    echo "✅ Network test PASSED: Process was successfully killed for violation."
    exit 0
  else
    echo "❌ Network test FAILED: Process was killed but should have been allowed!"
    exit 1
  fi
fi
