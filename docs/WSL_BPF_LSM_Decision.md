# SyscallCage: Suporte BPF LSM no Windows (WSL2) — "Kernel Plus"

## Como este documento está organizado

Primeiro a história completa — os problemas reais enfrentados e as decisões
tomadas para chegar ao `v0.2.0` funcionando de verdade. Depois o processo de
build reprodutível, para qualquer pessoa da comunidade Windows/WSL2 chegar
ao mesmo resultado **compilando o próprio kernel**, não baixando um binário
de terceiro. Ver a seção "Por que você compila, não baixa" para o motivo
dessa escolha.

---

## Parte 1 — A jornada até aqui (histórico técnico completo)

### O problema original: VirtualBox funcionava, mas com atraso inaceitável em SSH

O primeiro ambiente de teste fora do Linux nativo foi uma VM VirtualBox com
Ubuntu completo rodando dentro do Windows. O modo síncrono (BPF LSM) chegou
a ser validado ali — `syscallcage doctor` confirmava `bpf` na lista de LSM
ativos, e o modo preventivo funcionava. Mas o ambiente introduzia atraso
grande em conexões SSH, tornando o ciclo de desenvolvimento (editar → subir
→ testar) lento demais para iteração real.

### A escolha: WSL2 com kernel recompilado

WSL2 usa Hyper-V, mais leve que VirtualBox, com integração direta ao
sistema de arquivos do Windows — reduz drasticamente o atraso de SSH que
travava o fluxo anterior. O problema: o kernel que a Microsoft distribui
por padrão no WSL2 (`*-microsoft-standard-WSL2`) **não vem com
`CONFIG_BPF_LSM` habilitado**. Sem isso, `bpf` nunca aparece em
`/sys/kernel/security/lsm`, e o SyscallCage cai automaticamente para o modo
Reactive (fallback) — funcional, mas sem o bloqueio preventivo que é o
diferencial técnico do projeto.

A saída foi recompilar o kernel do WSL2 a partir da fonte oficial da
Microsoft, habilitando as flags necessárias. Esse kernel passou a ser
chamado, internamente, de **"Kernel Plus"**.

### O bug do deadlock/zumbi (resolvido antes do v0.2.0)

Ao testar o modo `watch` (supervisor) nesse ambiente, apareceu um problema
de processos zumbis (`Z` status) não sendo colhidos. Causa raiz: a leitura
bloqueante do ring buffer eBPF (`Monitor::start()`) ocupava a única thread
disponível, impedindo `waitpid()` de rodar a tempo de colher o processo
filho morto. **Correção**: `Monitor::start()` passou a rodar em thread
separada, liberando a thread principal exclusivamente para o ciclo de vida
do processo supervisionado. Validado sem zumbis depois da correção.

### O bug do verifier — a parte mais importante desta história

Com o Kernel Plus funcionando e `syscallcage doctor` confirmando modo Sync
disponível, a tentativa de anexar o hook `lsm_file_open` falhou no
carregamento:

```
error parsing BPF object: R1 is of type file but path is expected
```

**Causa raiz**: o código resolvia o offset do campo `f_path` dentro de
`struct file` em runtime (lendo o BTF do kernel via `bpftool`), e somava
esse offset manualmente a um ponteiro cru
(`(file_ptr as *const u8).add(offset)`). Isso produz um endereço de memória
correto, mas o verifier moderno do kernel rastreia **proveniência de
tipo**, não só valor de endereço — a soma manual "suja" o ponteiro,
fazendo-o perder o rastro de que era um `struct file` válido. O helper
`bpf_d_path()` exige estritamente um ponteiro com tipo verificado
(`PTR_TO_BTF_ID`), e rejeita o carregamento do programa inteiro quando essa
garantia não existe.

**Primeira tentativa de correção (insuficiente, não aceita como solução
final)**: substituir a soma manual por uma `struct file` escrita à mão em
Rust, com um campo `_padding: [u8; 64]` antes de `f_path`, na esperança de
que o offset conhecido em tempo de compilação bastasse para o verifier
aceitar. **Isso passou no verifier** — mas era exatamente a mesma classe de
bug já enfrentada duas vezes antes no projeto (offset `2708` cravado em
`task_struct`, depois offset `12`/`20` cravado em `sched_process_fork`):
um número mágico que funciona no ambiente testado e pode quebrar
silenciosamente em qualquer kernel com layout de struct diferente. Pior
ainda: a função que calculava o offset real via BTF continuava rodando e
logando sucesso, sem que o valor calculado fosse de fato usado — dando
falsa sensação de portabilidade.

**Correção definitiva, a que está em produção no `v0.2.0`**: gerar
bindings Rust reais a partir do BTF do kernel, usando `aya-tool generate`
(que usa `rust-bindgen` por baixo). O arquivo resultante (`vmlinux.rs`, com
quase 59 mil linhas, contendo a definição real de centenas de structs do
kernel) foi versionado no repositório. O acesso ao campo passou a ser feito
via campo de struct genuíno:

```rust
let path_ptr = unsafe { &raw mut (*file_ptr).__bindgen_anon_1.f_path };
```

Isso preserva a proveniência de tipo BTF até o momento da chamada de
`bpf_d_path`, porque o próprio compilador, através da relocation CO-RE
embutida nos bindings gerados, resolve o offset correto **em load-time**,
contra o BTF do kernel de destino — não mais um valor cravado em
compile-time. A struct manual com `_padding` foi completamente removida
do código, e a função de resolução de offset em runtime foi simplificada
para calcular apenas o que ainda precisa (`f_mode`, que é lido por um
helper diferente, sem a mesma exigência de tipo estrito).

Essa correção foi verificada, campo por campo, comparando o código-fonte
real contra a especificação técnica que a exigia — incluindo confirmação
de que o arquivo `vmlinux.rs` contém o cabeçalho de geração automática do
`rust-bindgen` (prova de que não foi escrito manualmente) e que nenhum
resquício de offset cravado permanece no código eBPF.

### Resultado: validação completa

Com a correção aplicada, a suíte de testes end-to-end rodou com sucesso no
modo síncrono, com o log confirmando:

```
Modo de enforcement síncrono (BPF LSM) ativado com sucesso.
```

Sem processos zumbis, sem falha de carregamento do verifier, com bloqueio
preventivo de verdade — o comando é negado antes de completar, não morto
depois. Essa é a base técnica sobre a qual o `v0.2.1` foi lançado.

---

## Parte 2 — Por que você compila, não baixa

Um binário de kernel roda com privilégio total sobre a máquina — não existe
"sandbox" para um kernel malicioso. Distribuir um binário `bzImage`
pré-compilado para desconhecidos baixarem e apontarem o WSL2 para ele
exigiria confiança cega de que nada foi alterado, sem meio prático de
verificação. Esse é exatamente o tipo de risco que o restante do projeto
(binário do `syscallcage`, checksum obrigatório, build reprodutível via
CI) foi desenhado para evitar.

A alternativa correta é documentar o **processo**, para que qualquer pessoa
compile o próprio kernel, auditando a configuração antes de compilar, sem
depender de confiar em ninguém.

---

## Parte 3 — Processo de build reprodutível

### Pré-requisitos (dentro do WSL2, distro Ubuntu/Debian padrão)

```bash
sudo apt update
sudo apt install -y build-essential flex bison libssl-dev libelf-dev \
  bc dwarves python3 git
```

### 1. Obtenha a fonte do kernel oficial da Microsoft para WSL2

```bash
git clone --depth 1 https://github.com/microsoft/WSL2-Linux-Kernel.git
cd WSL2-Linux-Kernel
```

### 2. Parta da configuração padrão da Microsoft, não do zero

```bash
cp Microsoft/config-wsl .config
```

### 3. Habilite as flags necessárias

```bash
scripts/config --enable CONFIG_BPF_LSM
scripts/config --enable CONFIG_BPF_SYSCALL
scripts/config --enable CONFIG_DEBUG_INFO_BTF
scripts/config --enable CONFIG_DEBUG_INFO_BTF_MODULES
```

**Nota de auditoria**: rode `scripts/config --state CONFIG_BPF_LSM` antes e
depois para confirmar a mudança — não assuma que o comando funcionou
silenciosamente, é o mesmo princípio de "nunca silêncio" aplicado ao
próprio processo de build.

### 4. Compile

```bash
make -j$(nproc) KCONFIG_CONFIG=.config
```

O binário resultante aparece em `arch/x86/boot/bzImage`. Este é o arquivo
que o `.wslconfig` vai referenciar — mas agora é **o seu próprio binário**,
compilado por você, a partir de fonte pública auditável e configuração
transparente, não um arquivo de origem desconhecida.

### 5. Copie para um diretório do Windows acessível pelo WSL2

```bash
cp arch/x86/boot/bzImage /mnt/c/Users/SeuUsuario/kernel-wsl2-bpf-plus
```

---

## Parte 4 — Configuração do WSL2 (`.wslconfig`)

Crie ou edite `C:\Users\SeuUsuario\.wslconfig`:

```ini
[wsl2]
kernel=C:\\Users\\SeuUsuario\\kernel-wsl2-bpf-plus
kernelCommandLine=lsm=landlock,lockdown,yama,safesetid,selinux,ima,bpf
```

*(As barras invertidas devem ser duplas `\\` no arquivo `.ini`.)*

No PowerShell, como Administrador:

```powershell
wsl --shutdown
```

---

## Parte 5 — Monte o `securityfs`

Toda vez que iniciar o WSL2, antes de rodar o SyscallCage:

```bash
sudo mount -t securityfs none /sys/kernel/security
```

---

## Parte 6 — Confirme e use

```bash
cat /sys/kernel/security/lsm   # confirma que "bpf" aparece na lista
```

```bash
cargo build --release --workspace
sudo ./target/release/syscallcage doctor   # confirma modo Sync disponível
sudo ./target/release/syscallcage watch --policy configs/sua-politica.yaml -- sleep 10
```

Log esperado:

```
Modo de enforcement síncrono (BPF LSM) ativado com sucesso.
```

---

## Resumo do que mudou desta versão do documento para a anterior

- Removida a instrução de baixar um binário de kernel pré-compilado.
- Adicionado processo de build completo, reprodutível, a partir da fonte
  oficial do kernel Microsoft para WSL2.
- Documentado o histórico técnico completo até aqui — incluindo o erro do
  verifier, a tentativa insuficiente de correção, e a correção definitiva
  via `aya-tool generate` — para que a decisão fique registrada e
  auditável, não apenas o resultado final.
