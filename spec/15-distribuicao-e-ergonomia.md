# SPEC GT-15 — Distribuição, binário único e ergonomia (conceitos aplicados, código próprio)

## Princípios (repetido de propósito em todo spec, sem exceção)

1. **Simplicidade de código**: a solução mais simples que atende ao requisito é a correta.
2. **Legibilidade de código**: nomes descrevem intenção; comentário explica o *porquê*, nunca o *o quê*.
3. **Manutenibilidade em qualquer tempo**: o código precisa ser fácil de manter e de crescer hoje, em 6 meses e em 3 anos, por outra pessoa, sem reconstruir raciocínio do zero.
4. **Complexidade justificada**: abstração nova só entra quando o simples comprovadamente não resolve. Quando entrar, comentar `// complexidade justificada: <motivo>`.
5. **Segurança zero trust**: o que não foi explicitamente permitido é negado. Vale inclusive para as decisões de infraestrutura deste spec.
6. **Testes sempre, em tudo**: nenhuma função pública sem teste. O que exige kernel real é testado manualmente, com procedimento explícito e escrito.
7. **Nenhum bug fica em silêncio**: todo erro, decisão e estado inesperado gera log estruturado.
8. **Não quebre o que já funciona**: modo `--pid`, modo `watch`, modo Sync (BPF LSM) e modo Reactive continuam idênticos após este spec. Tudo aqui é adição ou refatoração invisível ao usuário atual.

---

## FRONTEIRA LEGAL — leia antes de qualquer linha de código

O projeto `ai-jail` (Fabio Akita) é licenciado sob **GPL-3.0**. O SyscallCage é **MPL-2.0**. As duas licenças são **incompatíveis nesta direção**: incorporar código GPL-3.0 em projeto MPL-2.0 é violação de licença.

**O que é permitido, e é o que este spec faz**: aplicar *conceitos*. Ideia, estratégia de distribuição, decisão de UX e abordagem arquitetural **não são protegidas por copyright** — só a expressão concreta (o código) é. Implementar do zero, em Rust próprio, a mesma ideia que outro projeto teve é prática legal, comum e legítima em software livre.

**O que é PROIBIDO, sem exceção**:
- Abrir o código-fonte do `ai-jail` e transcrever, adaptar, traduzir ou "reescrever com outras palavras" qualquer trecho.
- Copiar arquivos de packaging (`PKGBUILD`, `flake.nix`, workflow de CI) dele, mesmo com modificação.
- Consultar o código dele durante a implementação deste spec.

**Procedimento obrigatório (clean-room)**: a implementação parte **exclusivamente** deste documento e da documentação pública/comportamento observável (README, docs, saída de terminal). Se surgir dúvida de "como ele fez", a resposta correta é **resolver do zero pela documentação oficial da ferramenta em questão** (crates.io, Arch Wiki, manual do Nix), nunca olhar o fonte dele.

Se, em qualquer momento, a implementação exigir consultar o código do `ai-jail` para prosseguir, isso é um **bloqueio a ser reportado**, não uma licença para copiar.

---

## Contexto: o que foi observado e por que vale aplicar

O `ai-jail` resolve problema adjacente ao nosso (contenção de agente de IA) por abordagem **diferente e complementar**: ele usa `bubblewrap` para isolar *ambiente* (namespace, bind mount, o que o processo **enxerga**). O SyscallCage restringe *syscall* (o que o processo **faz**). Não são concorrentes — são camadas distintas.

Onde ele está objetivamente à frente, e onde este spec ataca:

| Dimensão | ai-jail (observado) | SyscallCage (hoje) |
|---|---|---|
| Canais de instalação | brew, cargo, AUR, nix, mise, release assinado | `install.sh` + clone/build |
| Formato do binário | único, self-contained (~880KB) | dois arquivos (`syscallcage` + `syscallcage-ebpf`) |
| Config | descoberta automática por projeto | `--policy <caminho>` sempre obrigatório |
| Auditoria | flag `--dry-run` | só editando `mode:` no YAML |
| Doc de alternativas | `docs/sandbox-alternatives.md` explica por que escolheu bwrap | inexistente |

Nada disso é sobre segurança do enforcement (onde o SCC é mais forte). É sobre **fricção de adoção** — e fricção de adoção é o motivo real de ferramenta boa morrer sem usuário.

---

## PARTE 1 — Binário único self-contained (pré-requisito de tudo o resto)

### Por que isto só é possível AGORA, e não antes

Hoje o SCC distribui **dois artefatos**: o binário userspace `syscallcage` e o objeto eBPF `syscallcage-ebpf`, localizado em runtime por `locate_ebpf_binary()`, com fallback por variável de ambiente `SYSCALLCAGE_EBPF_PATH`. Isso é frágil (o binário pode não achar o companheiro) e **impede `cargo install`**, que instala apenas o binário do crate, sem arquivo companheiro.

A correção do **GT-14** (CO-RE real via `aya-tool generate`) destravou a solução: o objeto eBPF agora é **bytecode portável de verdade**, com relocations resolvidas em *load-time* contra o BTF do kernel de destino. Antes do GT-14, com offset cravado, embutir um objeto pré-compilado seria propagar o bug para todos os usuários. Agora, um único objeto compilado serve qualquer kernel compatível.

> **Nota de manutenibilidade (princípio 3)**: registre este parágrafo como comentário no topo do módulo que faz o embed. Quem ler daqui a dois anos precisa entender que o embed depende de CO-RE estar correto — e que quebrar CO-RE quebra o embed silenciosamente.

### Decisão de arquitetura (tomada, não é para debater)

O objeto eBPF é **embutido no binário userspace em tempo de compilação**, via `include_bytes!`. `locate_ebpf_binary()` e `SYSCALLCAGE_EBPF_PATH` são **removidos por completo** — não ficam como fallback, não ficam comentados, não ficam mortos (princípio 7: código morto que finge fazer algo é o que o GT-14 existiu para eliminar).

### Onde o objeto vive, e como isso NÃO vira o problema do kernel binário

O objeto eBPF pré-compilado é versionado no repositório em:

```
syscallcage-ebpf/prebuilt/syscallcage-ebpf.o
```

**Isto é categoricamente diferente de distribuir um kernel binário** (que rejeitamos no `docs/WSL_BPF_LSM_Decision.md`), por três razões que **devem ser documentadas** no `README.md` da pasta `prebuilt/`:

1. **É verificado pelo kernel antes de rodar.** O verifier do BPF rejeita bytecode malformado ou inseguro — não existe equivalente disso para um kernel binário, que roda em anel 0 sem ninguém conferindo.
2. **É reproduzível a partir do fonte no mesmo repositório.** O código-fonte que gerou o objeto está em `syscallcage-ebpf/src/`, no mesmo commit. Qualquer pessoa recompila e compara.
3. **A CI prova a reprodutibilidade a cada push** (ver 1.4 abaixo). Não é "confie em mim" — é "verifique você mesmo, e a máquina já verificou".

### 1.1 — Script de regeneração do objeto

```
scripts/build-ebpf.sh
```

Conteúdo exigido (comportamento, não texto literal):
- Compila o crate `syscallcage-ebpf` para `bpfel-unknown-none`, em `--release`, com nightly + `-Z build-std=core`.
- Copia o artefato resultante para `syscallcage-ebpf/prebuilt/syscallcage-ebpf.o`.
- Imprime o `sha256sum` do objeto gerado ao final (para conferência manual e para a CI).
- Falha com mensagem clara e código de saída não-zero se `bpf-linker` ou a toolchain nightly não estiverem presentes — **nunca** gera objeto parcial nem reaproveita o antigo silenciosamente (princípio 7).

### 1.2 — Embed no crate userspace

```rust
// syscallcage/src/monitor/mod.rs

/// Objeto eBPF embutido em tempo de compilação.
///
/// Isto substitui a antiga localização em runtime (`locate_ebpf_binary`),
/// removida no GT-15. O embed só é seguro porque o GT-14 migrou o acesso
/// a campos de struct do kernel para CO-RE real (`aya-tool generate`):
/// as relocations são resolvidas em load-time contra o BTF do kernel de
/// destino, então um único objeto pré-compilado é portável entre kernels.
/// Se algum dia o CO-RE for quebrado, este embed passa a propagar o bug
/// para todos os usuários -- ver GT-14 antes de mexer aqui.
const EBPF_OBJECT: &[u8] = include_bytes!("../../../syscallcage-ebpf/prebuilt/syscallcage-ebpf.o");
```

O carregamento passa a usar `EBPF_OBJECT` diretamente, em vez de ler arquivo do disco.

### 1.3 — Remoções obrigatórias

- `fn locate_ebpf_binary()` — deletada.
- Toda referência a `SYSCALLCAGE_EBPF_PATH` — deletada (código, README, doc, mensagem de erro).
- O check correspondente no `syscallcage doctor` ("Programa eBPF encontrado em: ...") é **substituído**, não removido — vira uma verificação de que o objeto embutido carrega e passa no verifier, que é informação mais útil e mais honesta. Ver Parte 5.

### 1.4 — CI: prova de reprodutibilidade (isto é o zero trust desta parte)

Novo job no workflow existente, rodando em **todo push e PR**, não só em tag:

```yaml
# .github/workflows/verify-ebpf.yml
name: Verify eBPF reproducibility
on: [push, pull_request]
jobs:
  verify:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Instala toolchain e bpf-linker
        run: |
          rustup toolchain install nightly --component rust-src
          cargo install bpf-linker
      - name: Recompila o eBPF a partir do fonte
        run: ./scripts/build-ebpf.sh
      - name: Falha se o objeto versionado divergir do recompilado
        run: |
          if ! git diff --exit-code --stat syscallcage-ebpf/prebuilt/syscallcage-ebpf.o; then
            echo "ERRO: o objeto eBPF versionado NAO corresponde ao fonte atual." >&2
            echo "Rode ./scripts/build-ebpf.sh e commite o resultado." >&2
            exit 1
          fi
```

**Critério de aceite desta parte**: se alguém alterar o `.rs` do eBPF e esquecer de regenerar o `.o`, a CI **quebra**. Se alguém trocar o `.o` por um objeto que não corresponde ao fonte, a CI **quebra**. É isto que torna o binário versionado auditável em vez de um ato de fé.

> **Se a compilação eBPF não for bit-a-bit determinística** (é possível que não seja, por causa de timestamps ou paths embutidos pelo LLVM), o critério muda para comparação **semântica**, não binária: comparar a saída de `llvm-objdump -d` dos dois objetos, ignorando metadados. **Reportar como achado se isso acontecer**, e ajustar o script — não desabilitar a verificação. Verificação desligada é pior que verificação inexistente, porque dá falsa sensação de segurança.

### Testes obrigatórios da Parte 1

- Teste unitário: `EBPF_OBJECT` não está vazio e tem tamanho plausível (> 1KB) — pega o caso de `include_bytes!` apontando para arquivo errado/vazio.
- Teste manual em kernel real: suíte E2E completa (5 cenários) passa com o binário único, nos dois modos (Sync e Reactive), sem nenhum arquivo companheiro presente no sistema.
- Teste manual: renomear/apagar `syscallcage-ebpf/prebuilt/` **após** a compilação e confirmar que o binário continua funcionando — prova que o embed é real e não há leitura de disco escondida.

---

## PARTE 2 — Publicação no crates.io

### Objetivo

```bash
cargo install syscallcage
```

Este é o canal de maior retorno pelo menor esforço: alcança todo desenvolvedor Rust sem nenhum trabalho de packaging por distro.

### Pré-requisito

Parte 1 **completa e testada**. Sem binário único, `cargo install` instala uma ferramenta quebrada, o que é pior que não publicar.

### 2.1 — Ajustes no `Cargo.toml` do crate `syscallcage`

Campos obrigatórios de metadado (crates.io recusa publicação sem alguns deles):

```toml
[package]
name = "syscallcage"
version = "0.3.0"
edition = "2021"
license = "MPL-2.0"
description = "Kernel-level guardrails for autonomous AI agents. Restricts what a process can do via eBPF, with synchronous (BPF LSM) enforcement when the kernel supports it."
repository = "https://github.com/rodrigoffreir3/syscallcage"
homepage = "https://rodrigofreire.pages.dev/syscallcage"
readme = "../README.md"
keywords = ["ebpf", "security", "sandbox", "ai-agents", "lsm"]
categories = ["command-line-utilities", "os::linux-apis"]
exclude = [
    "../scratch/*",
    "../*.tar.gz",
]
```

**Decisão sobre o crate `syscallcage-ebpf`**: **não é publicado no crates.io**. Ele não é biblioteca reutilizável, exige nightly + `bpf-linker` para compilar, e seu artefato já vai embutido no binário do crate principal. Publicá-lo seria complexidade sem propósito (princípio 4). Marcar explicitamente:

```toml
# syscallcage-ebpf/Cargo.toml
[package]
publish = false   # artefato vai embutido no crate `syscallcage` -- ver GT-15
```

### 2.2 — O problema do `include_bytes!` cruzando fronteira de crate

`cargo publish` empacota **apenas** os arquivos do diretório do crate. Um `include_bytes!("../../../syscallcage-ebpf/prebuilt/...")` aponta para **fora** do crate `syscallcage` e **vai falhar no build do crates.io**.

**Decisão (não deixar em aberto)**: mover o objeto pré-compilado para **dentro** do crate userspace:

```
syscallcage/prebuilt/syscallcage-ebpf.o
```

E o `include_bytes!` passa a ser local:

```rust
const EBPF_OBJECT: &[u8] = include_bytes!("../prebuilt/syscallcage-ebpf.o");
```

O `scripts/build-ebpf.sh` (Parte 1) copia o artefato para esse caminho. O `.gitignore` **não** ignora essa pasta — ela é versionada de propósito, e a CI da Parte 1.4 garante que corresponde ao fonte.

Ajustar o job de CI da Parte 1.4 para apontar para o caminho novo.

### 2.3 — Validação antes de publicar

```bash
cargo publish --dry-run -p syscallcage
```

Confirmar na listagem de arquivos empacotados que `prebuilt/syscallcage-ebpf.o` está incluído. **Se não estiver, `cargo install` produzirá binário quebrado** — este é o ponto de falha mais provável desta parte, então é verificação obrigatória, não opcional.

### Testes obrigatórios da Parte 2

- `cargo publish --dry-run` passa e lista o `.o` entre os arquivos empacotados.
- Teste em máquina limpa (a VM Oracle já usada para validar o `install.sh`): `cargo install syscallcage` a partir do crates.io, seguido de `syscallcage doctor`, funcionando **sem** clone do repositório, **sem** nightly e **sem** `bpf-linker` instalados.

---

## PARTE 3 — Descoberta automática de política por projeto

### Objetivo

```bash
cd ~/meu-projeto
sudo syscallcage watch -- claude-code     # sem --policy
```

Se existir `.syscallcage.yaml` no projeto, ele é usado automaticamente.

### 3.1 — Algoritmo de busca (exato, não é sugestão)

```rust
// syscallcage/src/policy/discovery.rs -- módulo novo

/// Procura `.syscallcage.yaml` a partir do diretório atual, subindo até a
/// raiz do projeto. A subida PARA no primeiro diretório que contenha `.git`
/// (inclusive), e NUNCA vai além dele.
///
/// Por que parar na raiz do git (decisão de segurança, princípio 5): subir
/// indefinidamente até `/` permitiria que uma política plantada em um
/// diretório-pai qualquer (ex.: `/tmp`, `/home`, ou um diretório
/// compartilhado) fosse aplicada sem o usuário perceber. O limite no
/// repositório é o escopo que o usuário conscientemente controla.
///
/// Se não houver `.git` em nenhum ancestral, a busca se limita ao
/// diretório atual, apenas -- nunca sobe às cegas.
pub fn discover_policy(start: &Path) -> Result<Option<PathBuf>, DiscoveryError> { /* ... */ }
```

### 3.2 — Validação de segurança do arquivo encontrado (obrigatória)

Antes de aceitar um arquivo descoberto automaticamente, verificar, **nesta ordem**:

```rust
/// Recusa arquivo de política descoberto automaticamente que não satisfaça
/// as garantias mínimas de confiança. Zero trust: uma política define o que
/// o agente PODE fazer -- se um terceiro consegue escrevê-la, ele consegue
/// abrir a jaula. Explícito (`--policy`) é escolha consciente do usuário e
/// não passa por esta checagem; descoberto automaticamente, sim.
fn validate_discovered_policy(path: &Path) -> Result<(), DiscoveryError> {
    // 1. É arquivo regular (não symlink, não fifo, não device).
    //    Symlink é recusado: um link plantado poderia apontar para
    //    política arbitrária fora do projeto.
    // 2. Não é gravável por "others" (permissão o+w).
    // 3. Dono é o usuário atual OU root.
    // Qualquer falha -> Err, com log explicando exatamente qual regra
    // falhou e qual o caminho do arquivo (princípio 7).
}
```

### 3.3 — Precedência (decidida, sem ambiguidade)

1. `--policy <caminho>` explícito → **sempre vence**, sem descoberta, sem checagem de 3.2 (é escolha consciente e explícita do usuário).
2. Sem `--policy` → tenta descoberta.
3. Descoberta achou e passou na validação → usa, **logando em nível `info` o caminho exato usado** (princípio 7: o usuário nunca pode ser surpreendido por uma política que ele não sabe que está ativa).
4. Descoberta achou mas **falhou** na validação → **erro fatal, aborta**. Nunca cai em "roda sem política" nem em "roda com política padrão" (zero trust: falha fecha, não abre).
5. Descoberta não achou nada → erro claro instruindo a usar `--policy` ou criar `.syscallcage.yaml`. Nunca inventar política padrão implícita.

### Testes obrigatórios da Parte 3

- `discover_policy` acha o arquivo no diretório atual.
- Acha em diretório-pai, parando corretamente na raiz do git.
- **Não** sobe além da raiz do git (teste com política plantada acima dela → deve retornar `None`).
- Sem `.git` em nenhum ancestral → busca só no diretório atual.
- `validate_discovered_policy` recusa symlink.
- Recusa arquivo com permissão `o+w`.
- Recusa arquivo de dono diferente do usuário atual e diferente de root.
- Precedência: `--policy` explícito ignora `.syscallcage.yaml` presente no diretório.
- Descoberta que falha na validação aborta o programa — **não** faz fallback silencioso.

---

## PARTE 4 — Flag `--dry-run`

### Objetivo

Auditar sem bloquear, sem precisar editar YAML.

### 4.1 — Semântica exata

`--dry-run` força `Mode::Monitor` em runtime, **independentemente** do que estiver escrito no campo `mode:` do YAML. Não altera o arquivo. Não persiste nada.

### 4.2 — Direção única (decisão de segurança)

A flag só pode tornar o comportamento **menos** agressivo (enforce → monitor). **Não existe** flag inversa que force `monitor → enforce`. Motivo: uma política escrita como `monitor` foi escrita assim de propósito, possivelmente por não estar validada ainda; permitir que uma flag de linha de comando a promova a `enforce` transformaria um teste em um kill acidental de processo de produção.

### 4.3 — Anúncio obrigatório e ruidoso (princípio 7)

Ao iniciar com `--dry-run`, **antes** de qualquer outro log:

```rust
if args.dry_run {
    logging::log(logging::Entry {
        level: "warn",
        component: "main",
        message: "MODO DRY-RUN ATIVO: nenhuma violacao sera bloqueada. \
                  A politica sera avaliada e registrada, mas o processo \
                  monitorado NAO sera interrompido.",
        ..Default::default()
    });
}
```

Nível `warn`, não `info` — o usuário precisa perceber que a proteção **não** está ativa. Um dry-run silencioso que o usuário esquece que ligou é exatamente o cenário de falsa sensação de segurança que este projeto existe para combater.

### Testes obrigatórios da Parte 4

- `--dry-run` com política `mode: enforce` → nenhum kill acontece, decisão é logada como `Action::Log`.
- `--dry-run` com política `mode: monitor` → comportamento idêntico (idempotente, não é erro).
- Sem `--dry-run` → comportamento atual preservado, sem regressão.
- O log de aviso é emitido em nível `warn` sempre que a flag está presente.

---

## PARTE 5 — `syscallcage doctor` atualizado

O check "Programa eBPF encontrado em: `<path>`" perde o sentido com o binário único. **Substituir** (não remover) por verificação mais útil:

```
✓ Objeto eBPF embutido: <tamanho> bytes, sha256 <hash-abreviado>
✓ Verifier do kernel aceitou o carregamento de teste dos programas LSM
```

O segundo item exige tentar carregar (sem anexar) os programas eBPF e reportar o resultado. **Isto é valioso**: é exatamente o teste que teria detectado o erro `R1 is of type file but path is expected` (GT-13) **antes** do usuário tentar usar a ferramenta de verdade, em vez de durante.

Se o carregamento de teste falhar, `doctor` reporta o erro completo do verifier e sai com código não-zero.

---

## PARTE 6 — Packaging por distribuição

### 6.1 — AUR (Arch Linux), dois pacotes

- `syscallcage-bin` — instala o binário pré-compilado do GitHub Release (x86_64).
- `syscallcage` — compila do fonte (necessário para aarch64 e para quem audita).

Ambos escritos **do zero**, a partir da documentação oficial do Arch (`PKGBUILD` reference / Arch Wiki), nunca a partir do `PKGBUILD` de outro projeto. Vivem em `packaging/aur/` no repositório.

Dependências declaradas: nenhuma em runtime (binário estático, sem `bubblewrap` nem nada — esta é, aliás, uma vantagem real do SCC sobre sandbox baseado em ferramenta externa, e vale registrar no `docs/alternatives.md`).

### 6.2 — Nix flake

`flake.nix` na raiz, permitindo:

```bash
nix run github:rodrigoffreir3/syscallcage
```

Escrito do zero pela documentação oficial do Nix.

### 6.3 — Homebrew: NÃO fazer, e documentar por quê

**Decisão explícita**: não criar tap do Homebrew. Homebrew é majoritariamente associado a macOS. Publicar lá sinalizaria suporte a macOS que **não existe e não vai existir tão cedo** (eBPF é Linux). Isso violaria a honestidade que o README inteiro sustenta — a pessoa instalaria e descobriria depois que não funciona.

Registrar esta decisão em `docs/alternatives.md` para não ser reaberta sem contexto daqui a seis meses.

---

## PARTE 7 — `docs/alternatives.md`

Documento novo, honesto, comparando o SyscallCage com as alternativas reais do campo. Não é peça de marketing — é a mesma disciplina do `docs/WSL_BPF_LSM_Decision.md`.

### Estrutura obrigatória

**Seção 1 — As três abordagens que existem**
- **Isolamento de ambiente** (namespace/bind mount — ex.: bubblewrap, e ferramentas construídas sobre ele como o `ai-jail`): controla o que o processo **enxerga**. Roda sem root. Não protege contra o que o processo faz **dentro** do que ele enxerga.
- **Sandbox pesado** (VM, container): isolamento mais forte, custo mais alto, muda o fluxo de trabalho.
- **Restrição de syscall no kernel** (SyscallCage, Landlock, seccomp): controla o que o processo **faz**. Não isola o ambiente.

**Seção 2 — Onde o SyscallCage ganha**
- Enforcement no kernel, para qualquer processo, sem exigir que o agente coopere ou tenha hook próprio.
- Modo síncrono (BPF LSM): nega a operação **antes** dela completar, não mata depois.
- Sem dependência externa em runtime.
- Política por domínio de rede resolvido via DNS, não por IP cru.

**Seção 3 — Onde o SyscallCage perde, dito sem maquiagem**
- Exige `sudo`. Ferramentas baseadas em namespace unprivileged (bubblewrap via `CLONE_NEWUSER`) não exigem.
- Modo síncrono exige `CONFIG_BPF_LSM=y`; em kernel sem isso, cai para reativo (mata depois, com janela real).
- No WSL2, o modo síncrono exige kernel recompilado (ver `docs/WSL_BPF_LSM_Decision.md`). Ferramentas de namespace funcionam no WSL2 padrão.
- Linux apenas. Alternativas baseadas em outras tecnologias já rodam em macOS.

**Seção 4 — Elas são complementares, não excludentes**
Isolar ambiente e restringir syscall são camadas diferentes. Rodar um agente dentro de um sandbox de namespace **e** sob SyscallCage é defesa em profundidade legítima, não redundância. Nenhuma das duas substitui a outra.

**Seção 5 — Quando NÃO usar o SyscallCage**
Se o workload for genuinamente hostil (não um agente de IA que pode errar, mas um adversário ativo), a resposta correta é VM descartável — não este projeto, não sandbox de processo. Dizer isso abertamente é a mesma honestidade que o README já pratica ao documentar limitações.

### Regra de tom (obrigatória)

Nenhuma frase depreciativa sobre projeto de terceiro. Descrever escolha técnica e trade-off, nunca qualidade ou mérito de quem fez. O objetivo é ajudar o leitor a escolher a ferramenta certa — inclusive quando a ferramenta certa não for a nossa.

O README principal ganha um link para este documento, próximo à seção "Por que ele é diferente".

---

## Ordem de implementação (sequencial, não pular)

1. **Parte 1** — binário único + script de build + CI de reprodutibilidade. Sem isto, nada da Parte 2 funciona.
2. **Parte 5** — `doctor` atualizado (depende da Parte 1, e é rápido).
3. **Parte 2** — crates.io. Publicar **só** depois do teste em máquina limpa passar.
4. **Parte 3** — descoberta de política.
5. **Parte 4** — `--dry-run`.
6. **Parte 7** — `docs/alternatives.md` (independente do código; pode ser escrito em paralelo).
7. **Parte 6** — AUR e Nix, por último (maior esforço, menor retorno marginal, e depende de release estável).

Cada etapa termina com `cargo test --workspace` e `cargo clippy` limpos antes da próxima começar (princípio 8).

---

## Critério de sucesso geral

- [ ] Binário único: nenhum arquivo companheiro necessário; suíte E2E completa passa nos dois modos.
- [ ] CI quebra se o `.o` versionado divergir do fonte eBPF.
- [ ] `locate_ebpf_binary()` e `SYSCALLCAGE_EBPF_PATH` removidos por completo — `grep` retorna vazio em todo o repositório, incluindo docs.
- [ ] `cargo install syscallcage` funciona em máquina limpa, sem nightly, sem `bpf-linker`, sem clone.
- [ ] `.syscallcage.yaml` descoberto automaticamente, com as três validações de segurança ativas e testadas.
- [ ] Descoberta que falha validação **aborta** — nunca faz fallback.
- [ ] `--dry-run` funciona e anuncia em `warn`.
- [ ] `doctor` reporta hash do objeto embutido e resultado do carregamento de teste no verifier.
- [ ] `docs/alternatives.md` publicado, com a Seção 3 (onde perdemos) escrita com o mesmo rigor da Seção 2.
- [ ] Modo `--pid`, modo `watch`, Sync e Reactive: nenhuma regressão.
- [ ] Nenhuma linha de código de terceiro incorporada; clean-room respeitado (ver Fronteira Legal).

---

## O que este spec explicitamente NÃO faz

- Não adota `bubblewrap` nem isolamento por namespace. É abordagem diferente, com trade-offs diferentes, e a decisão de não fazer sandbox está registrada desde o GT-09. Este spec pega **conceitos de distribuição e ergonomia**, não de arquitetura de enforcement.
- Não cria tap do Homebrew (ver 6.3).
- Não publica o crate `syscallcage-ebpf` no crates.io.
- Não adiciona suporte a macOS nem Windows nativo.
- Não muda nada da lógica de política, enforcer ou dos hooks eBPF — o comportamento de segurança é idêntico ao do `v0.2.1` após este spec.
