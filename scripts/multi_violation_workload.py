import socket, time, os
print(f"PID {os.getpid()}", flush=True)
time.sleep(2)

print("Tentando github.com (permitido)...", flush=True)
ip = socket.gethostbyname("github.com")
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(2)
s.connect((ip, 443))
print("github.com OK", flush=True)
s.close()

time.sleep(1)

print("Tentando google.com (deve ser bloqueado)...", flush=True)
ip2 = socket.gethostbyname("google.com")
s2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s2.settimeout(2)
s2.connect((ip2, 80))
print("google.com conectou -- ISSO NÃO DEVERIA ACONTECER", flush=True)
