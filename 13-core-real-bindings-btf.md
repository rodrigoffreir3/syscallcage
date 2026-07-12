# SPEC GT-13 — CO-RE real via bindings BTF (correção de tipo do verifier)

## Princípios (repetido de propósito em todo spec)

1. Simplicidade. 2. Legibilidade. 3. Manutenibilidade de curto/médio/longo
prazo. 4. Complexidade justificada. 5. Zero trust. 6. Testes em tudo,
sempre. 7. Log sempre, nunca silêncio. 8. Nunca quebrar o que já funciona
— o modo Reactive (kprobes/tracepoints) continua idêntico, sem nenhuma
mudança. Este spec toca exclusivamente nos hooks LSM do modo Sync.

## O problema, com causa raiz confirmada

Testado em WSL2 com kernel 6.1+ recompilado com `CONFIG_BPF_LSM=y`
funcionando (`syscallcage doctor` confirmou modo Sync detectado
corretamente). Na tentativa de anexar `lsm_file_open`, o verifier rejeitou
o carregamento:

```
error parsing BPF object: R1 is of type file but path is expected
...
41: (0f) r1 += r9   ; R1=trusted_ptr_file(...) R9=scalar(...)
44: (85) call bpf_d_path#147
R1 is of type file but path is expected
```

### Causa raiz exata

O código atual resolve o offset de `f_path` dentro de `struct file` **em
runtime**, via parsing de `bpftool btf dump` (GT-07/GT-08), e soma esse
offset a um ponteiro cru:

```rust
let path_ptr = unsafe { (file_ptr as *const u8).add(path_offset as usize) as *mut path };
```

Isso produz aritmética de ponteiro correta em **valor**, mas o verifier
moderno rastreia **proveniência de tipo**, não só endereço. Somar offset
manualmente a um `trusted_ptr_file` produz um ponteiro que o verifier não
consegue mais provar como `struct path` válida — vira `scalar`
"contaminado". `bpf_d_path()` exige estritamente `PTR_TO_BTF_ID` do tipo
`path`, então recusa carregar o programa. **Isto não é bug de
configuração nem de kernel específico — é limite estrutural da técnica
de "offset manual + soma de ponteiro" contra helpers que exigem tipo
verificado.** Funcionou até agora porque `bpf_probe_read_kernel` (usado
em outros pontos do código) aceita ponteiro cru sem exigir tipo — só
`bpf_d_path` tem essa exigência mais rígida.

## Decisão de arquitetura (já tomada, não é para debater)

### Migrar para CO-RE real via bindings gerados (`aya-tool generate`)

Em vez de calcular offset em runtime e somar manualmente, gera-se
**bindings Rust com layout de struct real**, extraídos do BTF do kernel
alvo, usando a ferramenta oficial do ecossistema `aya`. O acesso a campo
via struct gerada preserva a relocation CO-RE (`bpf_core_read`) e o tipo
BTF até o ponto de uso — exatamente o que `bpf_d_path` exige.

**Por que esta é a única rota aceita, e a alternativa (reconstruir path
via `dentry` walk manual) é rejeitada nesta spec**: parsing manual de
`dentry->d_parent` é código novo com casos de borda conhecidos e chatos
(bind mount, mount namespace, profundidade de path) que `bpf_d_path` já
resolve testado e mantido pelo kernel. Reimplementar isso é dívida
técnica desnecessária quando a ferramenta padrão do ecossistema resolve
o problema de forma mais simples e correta — complexidade não
justificada, princípio 4 violado se formos por aí.

### Setup: `aya-tool` gera os bindings, uma vez, versionado no repositório

```bash
# instala a ferramenta (uma vez, ambiente de dev)
cargo install --git https://github.com/aya-rs/aya --branch main aya-tool

# gera bindings para as structs que o SyscallCage precisa, a partir do
# BTF do kernel RODANDO NA MÁQUINA QUE ESTÁ GERANDO (isso importa --
# ver nota de portabilidade abaixo)
aya-tool generate file path linux_binprm > syscallcage-ebpf/src/vmlinux.rs
```

**Nota de portabilidade, importante**: os bindings gerados por
`aya-tool` usam `#[repr(C)]` com relocations CO-RE — isso significa que,
mesmo gerados a partir do BTF de UMA máquina, o binário resultante
**continua portável entre kernels diferentes**, porque a relocation CO-RE
é resolvida em **load-time** pelo `libbpf`/`aya` loader contra o BTF do
kernel de destino, não fixada em compile-time. Isto é a mesma garantia de
portabilidade que a spec GT-07 já buscava com offset dinâmico — só que
implementada da forma que o ecossistema realmente suporta pra helpers com
tipo estrito, em vez da aproximação manual que esbarrou no verifier.

### O arquivo gerado é artefato versionado, não gerado no CI

`vmlinux.rs` é grande (pode ter milhares de linhas, já que inclui toda
struct do kernel exposta via BTF, não só as três usadas). Ele entra no
`.gitignore`? **Não** — decisão explícita: versiona no repositório,
porque:
1. Gerar isso exige `aya-tool` instalado + acesso a `/sys/kernel/btf/vmlinux`
   — dependência de ambiente que não deveria ser obrigatória pra quem só
   quer compilar o projeto.
2. As relocations CO-RE dentro do arquivo já garantem portabilidade em
   runtime — não precisa regenerar por kernel de destino.
3. Só precisa regenerar se mudar quais structs/campos são necessários
   (raro, muda só se o spec evoluir), não a cada build.

```
# .gitignore -- NÃO adicionar vmlinux.rs aqui, ele é versionado de propósito
```

## Mudança no código eBPF (`syscallcage-ebpf/src/main.rs`)

### Antes (rejeitado pelo verifier)

```rust
let file_ptr: *mut file = unsafe { ctx.arg(0) };
let path_offset = get_f_path_offset(); // via mapa OFFSETS, resolvido em runtime
let path_ptr = unsafe { (file_ptr as *const u8).add(path_offset as usize) as *mut path };
let ret = unsafe { bpf_d_path(path_ptr, buf.as_mut_ptr() as *mut i8, 256) };
```

### Depois (usa struct gerada, preserva tipo BTF)

```rust
mod vmlinux; // arquivo gerado por aya-tool, incluído via módulo
use vmlinux::{file, path};
use aya_ebpf::helpers::bpf_d_path;
use aya_ebpf::helpers::gen::bpf_core_read; // acesso de campo com relocation CO-RE

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

    // Acesso de campo via struct gerada -- o macro/helper do aya preserva
    // a relocation CO-RE e o tipo BTF até aqui. Isto é o que resolve o
    // erro "R1 is of type file but path is expected": path_ptr chega em
    // bpf_d_path com proveniência de tipo intacta, não como scalar
    // derivado de soma manual.
    let path_ptr: *const path = unsafe { &(*file_ptr).f_path };

    let scratch_ptr = match unsafe { SCRATCH_PATH.get_ptr_mut(0) } {
        Some(ptr) => ptr,
        None => return -13,
    };

    let ret = unsafe { bpf_d_path(path_ptr as *mut _, scratch_ptr as *mut i8, 256) };
    if ret < 0 {
        return -13; // -EACCES -- falha em resolver path é negada por padrão, zero trust
    }

    // ... resto da lógica de decisão (is_sensitive_path, prefixos) permanece idêntica
}
```

**O que muda, e o que NÃO muda**: a lógica de decisão (checar
`is_sensitive_path`, varrer `DENY_ALWAYS_PREFIXES`/`ALLOW_READ_PREFIXES`)
é idêntica — só a forma de obter o `path_ptr` válido muda. Isto é
correção cirúrgica, não reescrita do hook.

### O mapa `OFFSETS` (userspace, `resolve_btf_offsets()`) — o que sobra dele

O offset de `f_mode` (usado pra checar `FMODE_WRITE`, lido via
`bpf_probe_read_kernel`, que **não** exige tipo estrito) continua
funcionando do jeito atual — não precisa migrar, porque não passa por
helper que exige `PTR_TO_BTF_ID`. Só o acesso a `f_path` (que alimenta
`bpf_d_path`) precisa da migração para struct gerada. **Decisão**: manter
os dois padrões coexistindo é aceitável aqui — não é inconsistência
arbitrária, é usar a técnica certa para cada exigência de helper
específica. Documentar isso em comentário no código, para não parecer
descuido.

## Mudança equivalente em `lsm_exec_check` (`linux_binprm` → `file` → `path`)

Mesmo padrão, uma camada a mais de indireção:

```rust
use vmlinux::{linux_binprm, file, path};

#[lsm(hook = "bprm_check_security")]
pub fn lsm_exec_check(ctx: LsmContext) -> i32 {
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    if !is_monitored(pid) {
        return 0;
    }

    let bprm: *const linux_binprm = unsafe { ctx.arg(0) };
    if bprm.is_null() {
        return 0;
    }

    let file_ptr: *const file = unsafe { (*bprm).file };
    if file_ptr.is_null() {
        return 0;
    }

    let path_ptr: *const path = unsafe { &(*file_ptr).f_path };
    // ... resto idêntico ao lsm_file_open a partir daqui
}
```

## Testes obrigatórios

- **Teste de carregamento** (o que falhou antes): `cargo build --release
  --workspace` seguido de attach real em kernel com `CONFIG_BPF_LSM=y` —
  critério de sucesso é o verifier aceitar o programa sem o erro `R1 is
  of type file but path is expected`. Isto não é testável via `cargo
  test` puro (depende de kernel real) — documentar como teste manual
  obrigatório antes de qualquer release.
- Suite E2E completa (os 5 cenários já validados) rodando em modo Sync
  desta vez, não só Reactive — GT-07 especificou isso mas nunca chegou a
  ser executado com sucesso até agora; esta correção é pré-requisito
  pra isso finalmente acontecer.
- Teste específico: arquivo em `deny_always` acessado em modo Sync
  retorna `EACCES` pro processo **sem** matar ele (comportamento já
  especificado no GT-07, agora finalmente testável de ponta a ponta).
- Confirma que o modo Reactive continua 100% funcional, sem regressão —
  ele não usa `bpf_d_path` nem os bindings novos, então não deveria ser
  afetado, mas a suite completa roda de novo pra ter certeza.

## O que este spec explicitamente NÃO faz

- Não implementa rede síncrona (`security_socket_connect`) — fora de
  escopo, seria GT futuro separado.
- Não remove o mapa `OFFSETS` nem o mecanismo de resolução de offset de
  `f_mode` — ele continua válido para o caso de uso que ainda serve.
- Não regenera `vmlinux.rs` automaticamente no CI — é artefato versionado,
  regeneração é manual e rara.

## Ordem de implementação

1. Instala `aya-tool`, gera `vmlinux.rs` com as três structs necessárias
   (`file`, `path`, `linux_binprm`), versiona no repositório.
2. Migra `lsm_file_open` para usar a struct gerada — só a obtenção do
   `path_ptr`, resto da lógica intocado.
3. Migra `lsm_exec_check` da mesma forma.
4. Compila e testa carregamento em kernel com `CONFIG_BPF_LSM=y` (o teste
   que falhou antes) — se passar, é sinal de que a causa raiz foi
   corrigida de verdade, não só mascarada.
5. Roda suite E2E completa em modo Sync.
6. Se tudo passar: documenta no README que modo Sync está validado de
   ponta a ponta (hoje o README ainda descreve isso como funcionando,
   mas nunca foi comprovado com sucesso real até este spec).

## Critério de sucesso

- [ ] `lsm_file_open` e `lsm_exec_check` carregam sem erro do verifier em
      kernel `6.1+` com `CONFIG_BPF_LSM=y`.
- [ ] Suite E2E completa passa em modo Sync, não só Reactive.
- [ ] Arquivo em `deny_always` retorna `EACCES` sem matar o processo, em
      modo Sync, comprovado por teste real (não só lido no código).
- [ ] Modo Reactive permanece 100% funcional, suite completa sem
      regressão.
- [ ] `vmlinux.rs` versionado no repositório, com comentário no topo
      explicando como foi gerado e quando regenerar.
