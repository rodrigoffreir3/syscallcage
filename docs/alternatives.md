# Alternativas e Trade-offs

Esta página detalha por que construímos o **SyscallCage** em vez de usar soluções existentes, e quando você deve preferir outras ferramentas.

## 1. Seccomp-BPF (Docker, Podman)

**O que é:** O padrão ouro do sandboxing no Linux. Filtra syscalls no momento em que entram no kernel.

**Limitações para Agentes IA:**
- **Assobiou, morre (geralmente):** Seccomp bloqueia matando a thread (SIGSYS) ou retornando `EPERM`. Não há contexto sobre *o que* a syscall tentava fazer (ex: qual arquivo abrir), apenas os registradores brutos.
- **Rígido:** Mudar políticas sem reiniciar o contêiner é complexo ou impossível.
- **Injecção de contexto:** Avaliar strings (como caminhos de arquivo) é impossível no filtro seccomp clássico (não há desreferenciamento de ponteiro).

**Veredito:** Se você quer sandboxing estático de *deploy*, use Seccomp (via Docker). Se você quer restringir um agente autônomo baseado no seu contexto (arquivos permitidos variam por prompt) dinamicamente, SyscallCage é superior.

## 2. AppArmor / SELinux

**O que são:** LSMs (Linux Security Modules) focados em controle de acesso mandatório (MAC).

**Limitações para Agentes IA:**
- **Sistema inteiro:** Exigem configuração ao nível do sistema operativo, com políticas em formatos próprios.
- **Complexidade Operacional:** Muito pesado para instanciar dinamicamente para cada novo agente gerado.
- **Não focado no processo:** Foca mais nos binários do que na intenção dinâmica do processo atual.

**Veredito:** Ótimos para defender o host permanentemente. Ruins para isolar scripts Python ou ferramentas dinâmicas em runtime.

## 3. Landlock

**O que é:** LSM moderno, desenhado para sandboxing não privilegiado (unprivileged).

**Limitações para Agentes IA:**
- **Escopo restrito:** Excelente para arquivos e rede básica, mas ainda imaturo para filtrar syscalls complexas (como `ptrace` em processos específicos).
- **Herança rígida:** Uma vez que as restrições são aplicadas, elas não podem ser relaxadas, apenas apertadas.
- **Sem visibilidade:** Falta infraestrutura de logs em tempo real comparável ao eBPF.

**Veredito:** O Landlock é o futuro do sandboxing em Linux, mas o BPF LSM (usado pelo SyscallCage) permite logs profundos e regras híbridas arquivo/syscall no mesmo mecanismo.

## 4. Falco (Sysdig)

**O que é:** Plataforma de detecção de ameaças focada em cloud-native via eBPF.

**Limitações para Agentes IA:**
- **Foco em auditoria:** Historicamente, Falco foi construído para *auditar*, não para *bloquear*. Bloqueio sincrono tem sido adicionado recentemente via bpf-lsm, mas não é a arquitetura principal.
- **Peso:** Traz uma bagagem imensa de regras de cloud (Kubernetes, Docker), sendo overkill para embutir na sua aplicação.

**Veredito:** Falco é para SecOps monitorando o cluster. SyscallCage é para o desenvolvedor construindo agentes de IA em código.

## Por que SyscallCage? (O Abordagem BPF LSM)

O SyscallCage usa **BPF LSM** (quando disponível) e **KProbes** (como fallback). Isso nos dá:
1. **Inspeção de Memória:** O eBPF consegue ler as strings do userspace, identificando caminhos de arquivo exatos.
2. **Logs Estruturados:** Cada violação envia um evento jsonl para o supervisor, permitindo que a aplicação reaja ("Agente X tentou ler arquivo Y").
3. **Ergonomia Zero-Setup:** O objeto eBPF já vem embutido no binário; não requer dependências C/LLVM no host.
4. **Resiliência:** Se o agente morre, a supervisão detecta e limpa os hooks. Se o SyscallCage morre, o agente é encerrado (via `PR_SET_PDEATHSIG`).
