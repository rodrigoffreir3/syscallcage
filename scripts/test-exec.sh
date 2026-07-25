#!/bin/bash
set -e

sudo -v

TMP_OUT=$(mktemp)
python3 scripts/exec_workload.py > "$TMP_OUT" 2>&1 &
WORKLOAD_PID=$!

echo "Started workload with PID $WORKLOAD_PID"

# Start syscallcage in background with the test-exec-policy
sudo ./target/release/syscallcage --pid $WORKLOAD_PID --policy configs/test-exec-policy.yaml &
CAGE_PID=$!

# Wait for workload
sleep 6

sudo kill -9 $CAGE_PID || true
kill -9 $WORKLOAD_PID 2>/dev/null || true

OUTPUT=$(cat "$TMP_OUT")
rm -f "$TMP_OUT"

if echo "$OUTPUT" | grep -q "Shell output: shell running"; then
  echo "❌ Exec test FAILED: shell executou e completou, deveria ter sido bloqueado"
  exit 1
else
  echo "✅ Exec test PASSED: shell não completou (bloqueado ou morto antes de terminar)"
  exit 0
fi
