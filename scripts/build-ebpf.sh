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

if ! rustup toolchain list | grep -q "nightly-2026-07-11"; then
    echo "Instalando toolchain nightly-2026-07-11 para reprodutibilidade..."
    rustup toolchain install nightly-2026-07-11 --component rust-src
fi

PROJECT_ROOT=$(git rev-parse --show-toplevel)
cd "$PROJECT_ROOT"

# Prepara diretório de destino
mkdir -p syscallcage/prebuilt

echo "Compilando syscallcage-ebpf..."
cd syscallcage-ebpf
# Reprodutibilidade: neutraliza o path absoluto do workspace, que varia entre
# CI (/home/runner/work/...) e máquina local (~/... ou C:/Users/...) e mudava
# a assinatura do .o final mesmo sem alteração real no código-fonte.
export CARGO_ENCODED_RUSTFLAGS="--remap-path-prefix=${PROJECT_ROOT}=/workspace"

cargo +nightly-2026-07-11 build --bin syscallcage-ebpf --target bpfel-unknown-none -Z build-std=core --release

echo "Copiando objeto gerado..."
cp "../target/bpfel-unknown-none/release/syscallcage-ebpf" "$PROJECT_ROOT/syscallcage/prebuilt/syscallcage-ebpf.o"

echo "Build eBPF concluído!"
sha256sum "$PROJECT_ROOT/syscallcage/prebuilt/syscallcage-ebpf.o"
