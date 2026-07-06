#!/bin/bash
set -e

sudo -v

TMP_OUT=$(mktemp)
python3 scripts/multi_violation_workload.py > "$TMP_OUT" 2>&1 &
WORKLOAD_PID=$!

echo "Started workload with PID $WORKLOAD_PID"

sudo ./target/release/syscallcage --pid $WORKLOAD_PID --policy configs/exemplo-claude-code.yaml &
CAGE_PID=$!

sleep 8

sudo kill -9 $CAGE_PID || true
kill -9 $WORKLOAD_PID 2>/dev/null || true

OUTPUT=$(cat "$TMP_OUT")
rm -f "$TMP_OUT"

if echo "$OUTPUT" | grep -q "github.com OK"; then
  echo "✅ First connection allowed successfully."
else
  echo "❌ First connection failed or didn't run."
  exit 1
fi

if echo "$OUTPUT" | grep -q "google.com conectou -- ISSO NÃO DEVERIA ACONTECER"; then
  echo "❌ Multi-violation test FAILED: Second connection should have been blocked!"
  exit 1
else
  echo "✅ Multi-violation test PASSED: Second connection blocked."
  exit 0
fi
