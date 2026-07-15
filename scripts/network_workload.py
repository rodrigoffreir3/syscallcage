import socket
import sys
import time
import os

print(f"Network workload running with PID {os.getpid()}", flush=True)
if len(sys.argv) < 2:
    print("Usage: python3 network_workload.py <target_host>", flush=True)
    sys.exit(1)

target = sys.argv[1]
time.sleep(3)

print(f"Attempting to connect to {target}...", flush=True)
try:
    ip = socket.gethostbyname(target)
    print(f"Resolved {target} to {ip}", flush=True)
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(2)
    s.connect((ip, 80))
    print("Connection succeeded!", flush=True)
    s.close()
except Exception as e:
    print(f"Connection/Resolution failed: {e}", flush=True)

time.sleep(2)
print("Finished workload.", flush=True)
