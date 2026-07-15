#!/bin/bash
set -e

# Run directly using the compiled release target binary

# Create a test directory in the native Linux filesystem to avoid WSL2 9p filesystem tracepoint bugs
TEST_DIR="/tmp/syscallcage-test"
mkdir -p $TEST_DIR

echo "SECRET=12345" > $TEST_DIR/.env

# Create a dummy script that will sleep, then try to read the .env file
cat << 'EOF' > $TEST_DIR/dummy_workload.py
import sys
import time
import os

print(f"Dummy workload running with PID {os.getpid()}", flush=True)
time.sleep(5)
print("Attempting to read .env file...", flush=True)
try:
    with open(".env", "r") as f:
        print(f.read(), flush=True)
except Exception as e:
    print(f"Failed to read: {e}", flush=True)
print("Finished reading.", flush=True)
time.sleep(10)
EOF
chmod +x $TEST_DIR/dummy_workload.py

echo "Starting dummy process..."
cd $TEST_DIR
python3 dummy_workload.py &
DUMMY_PID=$!
cd - > /dev/null

echo "Dummy process PID: $DUMMY_PID"
echo "Applying syscallcage policy..."

# Run syscallcage to monitor the dummy process (sem sudo: setcap já garante as caps necessárias)
./target/release/syscallcage --pid $DUMMY_PID --policy configs/exemplo-claude-code.yaml &
CAGE_PID=$!

# Give the dummy script time to wake up and read the file
sleep 8

echo "Checking if dummy process was killed..."
if kill -0 $DUMMY_PID 2>/dev/null; then
  echo "❌ E2E Test Failed: Dummy process is still alive! The policy did not enforce the restriction."
  # Cleanup
  kill $CAGE_PID 2>/dev/null || true
  kill $DUMMY_PID || true
  rm -rf $TEST_DIR
  exit 1
else
  echo "✅ E2E Test Passed: Dummy process was successfully killed by syscallcage."
  kill $CAGE_PID 2>/dev/null || true
  rm -rf $TEST_DIR
  exit 0
fi
