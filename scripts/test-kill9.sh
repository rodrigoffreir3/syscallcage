#!/bin/bash
# Teste de robustez do syscallcage com kill -9 (desconexão e limpeza eBPF)
set -e

# Garante permissões de sudo
sudo -v

TEST_DIR="/tmp/syscallcage-kill9-test"
mkdir -p "$TEST_DIR"

# Cria workload dummy que faz leituras periódicas
cat << 'EOF' > "$TEST_DIR/workload.py"
import time
import os
import sys

print(f"[Workload] Iniciado com PID {os.getpid()}", flush=True)
for i in range(15):
    time.sleep(1)
    # Tenta ler um arquivo inofensivo
    try:
        with open("/etc/hostname", "r") as f:
            data = f.read().strip()
            print(f"[Workload] Lendo /etc/hostname: {data}", flush=True)
    except Exception as e:
        print(f"[Workload] Falha ao ler /etc/hostname: {e}", flush=True)
print("[Workload] Encerrado normalmente", flush=True)
EOF
chmod +x "$TEST_DIR/workload.py"

# 1. Inicia o workload
echo "--- Iniciando o processo monitorado (workload) ---"
python3 "$TEST_DIR/workload.py" &
WORKLOAD_PID=$!
sleep 1

# 2. Inicia o syscallcage
echo "--- Iniciando o syscallcage ---"
sudo ./target/release/syscallcage --pid $WORKLOAD_PID --policy configs/exemplo-claude-code.yaml &
CAGE_PID=$!
sleep 2

# 3. Verifica se os programas eBPF estão carregados no kernel
echo "--- Programas eBPF carregados no kernel ANTES do kill -9 ---"
sudo bpftool prog show | grep -E "handle_open|handle_fork" || echo "Nenhum programa eBPF encontrado"

# 4. Mata o syscallcage abruptamente com kill -9
echo "--- Matando o syscallcage abruptamente com kill -9 ---"
sudo pkill -9 syscallcage || true
sleep 2

# 5. Verifica se o processo morreu
if pgrep -x syscallcage >/dev/null; then
    echo "❌ Erro: O syscallcage não morreu após SIGKILL!"
    exit 1
else
    echo "✅ Confirmado: O processo do syscallcage morreu."
fi

# 6. Verifica se os programas eBPF foram descarregados do kernel automaticamente
echo "--- Programas eBPF carregados no kernel DEPOIS do kill -9 ---"
BPF_PROGS=$(sudo bpftool prog show | grep -E "handle_open|handle_fork" || true)
if [ -z "$BPF_PROGS" ]; then
    echo "✅ Sucesso: Todos os programas eBPF do syscallcage foram limpos automaticamente pelo kernel!"
else
    echo "❌ Erro: Programas eBPF ainda pendentes no kernel:"
    echo "$BPF_PROGS"
    exit 1
fi

# 7. Verifica se o workload sobreviveu e continua rodando
echo "--- Verificando se o workload continua rodando normalmente ---"
if kill -0 $WORKLOAD_PID 2>/dev/null; then
    echo "✅ Sucesso: O processo workload sobreviveu e continua ativo."
else
    echo "❌ Erro: O workload morreu ou travou após o kill -9 do enforcer!"
    exit 1
fi

# Aguarda o workload terminar
sleep 6
kill -9 $WORKLOAD_PID 2>/dev/null || true
rm -rf "$TEST_DIR"
echo "--- Teste de kill -9 concluído com sucesso total! ---"
exit 0
