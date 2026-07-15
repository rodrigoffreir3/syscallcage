#!/bin/bash
# Teste E2E de geração de política a partir de log de eventos
set -e

# Garante permissões de sudo
sudo -v

TEST_DIR="/tmp/syscallcage-gen-policy-test"
mkdir -p "$TEST_DIR"

echo "SECRET=99999" > "$TEST_DIR/.env"

# 1. Cria o workload dinâmico
cat << 'EOF' > "$TEST_DIR/workload.py"
import time
import os
import sys
import subprocess

print(f"[Workload] Iniciado com PID {os.getpid()}", flush=True)
time.sleep(3)

# Operações legítimas
print("[Workload] Tentando ler /etc/hostname...", flush=True)
try:
    with open("/etc/hostname", "r") as f:
        _ = f.read()
except Exception as e:
    print(f"[Workload] Falha ao ler /etc/hostname: {e}", flush=True)

print("[Workload] Tentando ler configs/exemplo-claude-code.yaml...", flush=True)
try:
    with open("/home/momos/Desktop/agent-cage/configs/exemplo-claude-code.yaml", "r") as f:
        _ = f.read()
except Exception as e:
    print(f"[Workload] Falha ao ler config: {e}", flush=True)

print("[Workload] Tentando gravar em /tmp/workload_out.txt...", flush=True)
try:
    with open("/tmp/workload_out.txt", "w") as f:
        f.write("OK")
except Exception as e:
    print(f"[Workload] Falha ao gravar: {e}", flush=True)

# Operação sensível que deve ser filtrada silenciosamente
print("[Workload] Tentando ler o arquivo .env...", flush=True)
try:
    with open(".env", "r") as f:
        _ = f.read()
except Exception as e:
    print(f"[Workload] Falha ao ler .env: {e}", flush=True)

# Execução de subprocesso (syscall perigosa)
print("[Workload] Tentando rodar sh subprocess...", flush=True)
try:
    subprocess.run(["/bin/sh", "-c", "echo 'subproc ok'"], check=True)
except Exception as e:
    print(f"[Workload] Falha ao executar subprocesso: {e}", flush=True)

time.sleep(5)
print("[Workload] Concluído", flush=True)
EOF
chmod +x "$TEST_DIR/workload.py"

# Inicia o workload
echo "--- Passo 1: Iniciando o workload em background ---"
cd "$TEST_DIR"
python3 workload.py &
WORKLOAD_PID=$!
cd - > /dev/null
sleep 1

# Inicia o syscallcage em modo MONITOR com gravação de log
echo "--- Passo 2: Monitorando o workload com --log-file ---"
LOG_FILE="$TEST_DIR/sessao.jsonl"
sudo ./target/release/syscallcage --pid $WORKLOAD_PID --policy configs/exemplo-monitor-mode.yaml --log-file "$LOG_FILE" &
CAGE_PID=$!

# Aguarda a conclusão do workload
echo "--- Aguardando o workload gerar eventos ---"
sleep 6

# Garante encerramento do monitor
sudo pkill -9 syscallcage || true
sleep 1

# Exibe o conteúdo do log
echo "--- Conteúdo do log gravado (JSONL) ---"
cat "$LOG_FILE"

# Gera a política a partir do log
echo "--- Passo 3: Gerando a política a partir do log ---"
POLICY_OUT="$TEST_DIR/politica_gerada.yaml"
./target/release/syscallcage generate-policy --from-log "$LOG_FILE" --output "$POLICY_OUT"

echo "--- Passo 4: Política YAML Gerada ---"
cat "$POLICY_OUT"

# Validações estruturais na política gerada
echo "--- Passo 5: Validando regras da política gerada ---"
if grep -q "mode: enforce" "$POLICY_OUT"; then
    echo "✅ Sucesso: O modo da política gerada é 'enforce'."
else
    echo "❌ Erro: O modo da política gerada deveria ser 'enforce'."
    exit 1
fi

if grep -q "/etc/\*\*" "$POLICY_OUT"; then
    echo "✅ Sucesso: A regra de leitura do /etc foi generalizada para /etc/**."
else
    echo "❌ Erro: A leitura do /etc não foi generalizada corretamente."
    exit 1
fi

if grep -q "\.env/\*\*" "$POLICY_OUT"; then
    echo "❌ Erro: O arquivo .env foi indevidamente incluído na allowlist!"
    exit 1
else
    echo "✅ Sucesso: O arquivo .env foi corretamente omitido da allowlist de leitura."
fi

if grep -q "execve:/bin/sh" "$POLICY_OUT"; then
    echo "✅ Sucesso: A syscall perigosa execve:/bin/sh foi incluída em deny_syscalls."
else
    echo "❌ Erro: A syscall execve:/bin/sh deveria constar em deny_syscalls."
    exit 1
fi

# Cleanup
rm -rf "$TEST_DIR"
echo "--- Teste E2E de geração de política concluído com sucesso absoluto! ---"
exit 0
