#!/bin/bash
set -euo pipefail

# Scripts de build do eBPF
echo "Iniciando build do eBPF..."

# Verifica dependências
if ! command -v cargo &> /dev/null; then
    echo "ERRO: cargo não encontrado" >&2
    exit 1
fi

if ! command -v bpf-linker &> /dev/null; then
    echo "ERRO: bpf-linker não encontrado. Instale com 'cargo install bpf-linker'" >&2
    exit 1
fi

if ! rustup toolchain list | grep -q "nightly"; then
    echo "ERRO: toolchain nightly não encontrada. Instale com 'rustup toolchain install nightly --component rust-src'" >&2
    exit 1
fi

PROJECT_ROOT=$(git rev-parse --show-toplevel)
cd "$PROJECT_ROOT"

# Prepara diretório de destino
mkdir -p syscallcage/prebuilt

echo "Compilando syscallcage-ebpf..."
cd syscallcage-ebpf
cargo +nightly build --bin syscallcage-ebpf --target bpfel-unknown-none -Z build-std=core --release

echo "Copiando objeto gerado..."
cp "../target/bpfel-unknown-none/release/syscallcage-ebpf" "$PROJECT_ROOT/syscallcage/prebuilt/syscallcage-ebpf.o"

echo "Build eBPF concluído!"
sha256sum "$PROJECT_ROOT/syscallcage/prebuilt/syscallcage-ebpf.o"
