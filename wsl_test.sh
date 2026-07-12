#!/bin/bash
set -e

echo "Compiling eBPF object locally..."
cd syscallcage-ebpf
cargo +nightly build --target bpfel-unknown-none -Z build-std=core --release
cd ..

echo "Compiling userspace with zombie fix..."
sudo mount -t securityfs none /sys/kernel/security 2>/dev/null || true
cargo build --release --package syscallcage

# Start syscallcage
sudo SYSCALLCAGE_EBPF_PATH="$(pwd)/target/bpfel-unknown-none/release/syscallcage-ebpf" ./target/release/syscallcage watch --policy configs/test-exec-policy.yaml -- sleep 10 &
CAGE_PID=$!

sleep 2

# Find the sleep process (don't restrict to parent PID because of sudo)
SLEEP_PID=$(pgrep sleep | head -n 1)

if [ -z "$SLEEP_PID" ]; then
    echo "Sleep process not found! Syscallcage might have failed to start it."
    sudo kill $CAGE_PID || true
    exit 1
fi

echo "Killing sleep process $SLEEP_PID"
sudo kill -9 $SLEEP_PID

sleep 2

# Check if it became a zombie
if ps -el | awk '{print $2, $14}' | grep -E "^Z\s+sleep$" > /dev/null; then
    echo "TEST FAILED: Zombie process found!"
    ps -el | grep "sleep"
    sudo kill $CAGE_PID || true
    exit 1
else
    echo "TEST PASSED: No zombie processes!"
fi

sudo kill $CAGE_PID || true
wait $CAGE_PID || true
echo "All tests completed successfully."
