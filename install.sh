#!/bin/sh
set -e

REPO="rodrigoffreir3/syscallcage"
INSTALL_DIR="${SYSCALLCAGE_INSTALL_DIR:-$HOME/.local/bin}"

# 1. Detecta SO e arquitetura -- falha cedo e com mensagem clara se não suportado
os=$(uname -s)
if [ "$os" != "Linux" ]; then
  echo "SyscallCage roda apenas em Linux (usa eBPF, tecnologia de kernel Linux)." >&2
  echo "Detectado: $os. Instalação abortada." >&2
  exit 1
fi

arch=$(uname -m)
case "$arch" in
  x86_64)  target="x86_64-unknown-linux-gnu" ;;
  aarch64) target="aarch64-unknown-linux-gnu" ;;
  *)
    echo "Arquitetura '$arch' não suportada. Alvos disponíveis: x86_64, aarch64." >&2
    exit 1
    ;;
esac

# 2. Checa versão de kernel minimamente viável (5.x+) -- aviso, não bloqueio
kernel_major=$(uname -r | cut -d. -f1)
if [ "$kernel_major" -lt 5 ]; then
  echo "Aviso: kernel $(uname -r) detectado. SyscallCage foi testado em kernel 5.x+." >&2
  echo "Pode não funcionar corretamente em kernels mais antigos." >&2
fi

# 3. Baixa a última release para o target detectado
latest_url="https://github.com/${REPO}/releases/latest/download/syscallcage-${target}.tar.gz"
tmp_dir=$(mktemp -d)

echo "Baixando SyscallCage para ${target}..."
curl -fsSL "$latest_url" -o "$tmp_dir/syscallcage.tar.gz"
curl -fsSL "${latest_url}.sha256" -o "$tmp_dir/syscallcage.tar.gz.sha256"

# 4. Verifica checksum -- SEMPRE, nunca opcional, isso não é frescura
cd "$tmp_dir"
if ! sha256sum -c syscallcage.tar.gz.sha256 >/dev/null 2>&1; then
  echo "ERRO: checksum não confere. Download corrompido ou adulterado. Abortando." >&2
  rm -rf "$tmp_dir"
  exit 1
fi

# 5. Extrai e instala
mkdir -p "$INSTALL_DIR"
tar -xzf syscallcage.tar.gz -C "$INSTALL_DIR"
chmod +x "$INSTALL_DIR/syscallcage" "$INSTALL_DIR/syscallcage-ebpf"
rm -rf "$tmp_dir"

# 6. Confirma que está no PATH -- se não estiver, avisa exatamente o que fazer,
#    não deixa o usuário "descobrir sozinho" por que o comando não roda
case ":$PATH:" in
  *":$INSTALL_DIR:"*) ;;
  *)
    echo ""
    echo "SyscallCage instalado em $INSTALL_DIR, que não está no seu PATH."
    echo "Adicione esta linha ao seu ~/.bashrc ou ~/.zshrc:"
    echo ""
    echo "    export PATH=\"\$PATH:$INSTALL_DIR\""
    echo ""
    ;;
esac

echo "SyscallCage instalado com sucesso."
echo "Verifique o ambiente com: syscallcage doctor"
