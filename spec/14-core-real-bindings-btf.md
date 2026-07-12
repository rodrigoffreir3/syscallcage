# SPEC GT-14 — Correção do GT-13: CO-RE real, sem offset cravado disfarçado

## Princípios (repetido de propósito em todo spec)

1. Simplicidade. 2. Legibilidade. 3. Manutenibilidade de curto/médio/longo
prazo. 4. Complexidade justificada. 5. Zero trust. 6. Testes em tudo,
sempre. 7. Log sempre, nunca silêncio. 8. Nunca quebrar o que já funciona.

## Diagnóstico: o que foi entregue no v0.2.0 não é o que o GT-13 pediu

O GT-13 especificou explicitamente: gerar bindings reais via `aya-tool
generate` a partir do BTF do kernel, para que o acesso a `f_path` preserve
relocation CO-RE e seja portável entre kernels via resolução em
**load-time**, não em compile-time.

O que foi implementado em vez disso:

```rust
#[cfg(target_arch = "bpf")]
#[repr(C)]
pub struct file {
    pub _padding: [u8; 64],
    pub f_path: path,
}
```

Isto é uma struct **escrita à mão**, com um número mágico (`64`) cravado
no código-fonte, definindo onde o Rust *acredita* que `f_path` fica
dentro de `struct file`. Isto passou no verifier — mas passar no
verifier não é o critério de aceite deste projeto. **É exatamente a
mesma classe de bug que já foi caçada e corrigida duas vezes antes
(offset `2708` em `task_struct`, depois `12`/`20` em
`sched_process_fork`)**, agora reintroduzida de forma mais difícil de
notar, porque:

1. O valor `64` é plausível e "parece" ter vindo de algum lugar
   legítimo.
2. `resolve_btf_offsets()` **continua rodando**, lendo o BTF real,
   calculando `f_path_off` corretamente, e logando "Offsets dinâmicos
   estruturais resolvidos" — dando a falsa impressão de que o sistema é
   portável. **O valor calculado nunca é usado pelo hook.** Isso é pior
   que um offset hardcoded assumido — é infraestrutura de correção
   coexistindo, sem efeito, ao lado do bug, mascarando que o bug existe.

Isto não é aceitável como estado final. Corrige-se agora, seguindo
exatamente a rota que o GT-13 original especificou, sem atalho.

## O que este spec exige, sem ambiguidade

### 1. Gerar bindings reais via `aya-tool generate` — não escrever struct à mão

```bash
cargo install --git https://github.com/aya-rs/aya --branch main aya-tool
aya-tool generate file path linux_binprm > syscallcage-ebpf/src/vmlinux.rs
```

Isto é executado **uma vez**, no kernel de desenvolvimento (o WSL2
recompilado já disponível), e o arquivo resultante é **versionado no
repositório** — não gerado no CI, não gerado a cada build (motivo já
documentado no GT-13: a relocation CO-RE dentro do arquivo gerado é
resolvida em load-time contra o BTF do kernel de destino, então o mesmo
arquivo serve para qualquer kernel, não precisa regenerar por ambiente).

**Critério de aceite desta etapa**: o arquivo `vmlinux.rs` gerado contém
as structs reais extraídas do BTF, com anotação/relocation CO-RE — não
uma struct escrita manualmente por um humano ou por um agente adivinhando
o layout. Se `aya-tool` não estiver disponível ou a geração falhar por
qualquer motivo, isto é um **bloqueio a ser reportado**, não uma licença
para voltar à struct manual como "solução temporária". Zero trust
aplicado ao próprio processo de build: se não dá pra fazer certo, para e
avisa — não finge que fez.

### 2. Remover a struct manual `file`/`path`/`linux_binprm` do `main.rs`

O código atual em `syscallcage-ebpf/src/main.rs` (structs com
`_padding: [u8; 64]`) é **deletado**, não comentado, não deixado como
fallback. Substituído por `use vmlinux::{file, path, linux_binprm};` a
partir do módulo gerado no passo 1.

### 3. Remover a resolução de `f_path_off`/`bprm_file_off` que não é mais necessária

Se os bindings gerados por `aya-tool` resolvem `f_path` via relocation
CO-RE automaticamente (que é o esperado), então `resolve_btf_offsets()`
não precisa mais calcular `f_path_off` nem `bprm_file_off` manualmente —
isso passa a ser redundante. **Decisão**: remover essas duas resoluções
específicas da função, mantendo apenas `f_mode_off` (que continua
necessário, pois `f_mode` é lido via `bpf_probe_read_kernel`, helper que
não usa relocation CO-RE e não tem o mesmo mecanismo automático).

Não deixar código morto: se `f_path_off`/`bprm_file_off` deixam de ser
usados, a função, o índice no mapa `OFFSETS`, e o log correspondente são
removidos junto — não apenas o consumo. Código morto que finge fazer
algo é exatamente o problema que este spec existe para eliminar.

```rust
// resolve_btf_offsets() após a correção -- só resolve o que ainda é
// necessário. Assinatura muda de (u32, u32, u32) para u32 (só f_mode).
fn resolve_btf_offsets() -> u32 {
    // ... lógica igual, mas só extrai f_mode_offset
}
```

### 4. `lsm_file_open` e `lsm_exec_check` usando os bindings gerados

```rust
mod vmlinux;
use vmlinux::{file, path, linux_binprm};

#[lsm(hook = "file_open")]
pub fn lsm_file_open(ctx: LsmContext) -> i32 {
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    if !is_monitored(pid) {
        return 0;
    }

    let file_ptr: *const file = unsafe { ctx.arg(0) };
    if file_ptr.is_null() {
        return 0;
    }

    // Acesso via struct GERADA a partir do BTF real (aya-tool), com
    // relocation CO-RE preservando proveniência de tipo até bpf_d_path.
    // NÃO é struct escrita à mão -- ver GT-14 para o motivo desta
    // exigência.
    let path_ptr: *const path = unsafe { &(*file_ptr).f_path };

    // ... resto da lógica (is_sensitive_path, prefixos) permanece idêntica
}
```

## Testes obrigatórios (além dos já exigidos pelo GT-13 original)

- **Teste de proveniência do binding**: confirma, inspecionando
  `vmlinux.rs`, que o arquivo tem cabeçalho/comentário indicando que foi
  gerado por `aya-tool generate` (a ferramenta insere esse tipo de
  marcação) — não um arquivo criado manualmente com o mesmo nome para
  enganar a checagem.
- Suite E2E completa em modo Sync, repetida com o binding real — critério
  de sucesso idêntico ao GT-13 (`EACCES` sem matar processo, etc).
- **Teste de portabilidade, novo**: se houver acesso a um segundo kernel
  diferente do WSL2 usado no desenvolvimento (Lubuntu bare metal, ou
  outra VM), rodar a suite completa lá também. Isto é o teste que a
  versão anterior (offset `64` cravado) não seria capaz de passar de
  forma confiável — é o que prova que a correção deste spec resolveu o
  problema de verdade, não só localmente.
- Confirma, por leitura de código (não só por rodar teste), que nenhuma
  struct com campo `_padding: [u8; N]` de tamanho mágico permanece em
  `syscallcage-ebpf/src/main.rs`.

## Critério de sucesso

- [ ] `vmlinux.rs` existe, é gerado por `aya-tool generate` de verdade
      (verificável pela origem/formato do arquivo), versionado no
      repositório.
- [ ] Nenhuma struct `file`/`path`/`linux_binprm` escrita manualmente
      resta em `main.rs` do crate eBPF.
- [ ] `resolve_btf_offsets()` só calcula o que ainda é necessário
      (`f_mode`); código relativo a `f_path_off`/`bprm_file_off` removido
      por completo, não deixado morto.
- [ ] Suite E2E em modo Sync passa com os bindings reais.
- [ ] Se houver acesso a segundo ambiente de kernel diferente, suite
      passa lá também, confirmando portabilidade de verdade.
- [ ] `git log` mostra este spec como commit próprio, com mensagem que
      deixa claro que é correção de uma implementação anterior
      insuficiente — não silenciosamente misturado a outro commit,
      para manter histórico honesto do que aconteceu.
