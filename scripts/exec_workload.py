import sys
import time
import subprocess
import os

print(f"Exec workload running with PID {os.getpid()}", flush=True)
time.sleep(3)

print("Attempting to run /bin/sh...", flush=True)
try:
    res = subprocess.run(["/bin/sh", "-c", "echo shell running"], capture_output=True, text=True)
    print(f"Shell output: {res.stdout.strip()}", flush=True)
except Exception as e:
    print(f"Shell failed: {e}", flush=True)

time.sleep(2)
print("Finished exec workload.", flush=True)
