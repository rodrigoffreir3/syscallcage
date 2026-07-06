# Agent Cage

**Deixe sua IA autônoma trabalhar sozinha — sem perder o controle sobre o que ela pode tocar.**

Você usa Claude Code, Cursor, ou qualquer agente de IA que edita arquivo e roda comando sozinho no seu computador. Funciona bem, mas sempre fica aquele friozinho: *e se ele ler meu `.env` sem eu perceber? E se um prompt malicioso escondido numa issue do GitHub fizer ele vazar minha API key? E se ele rodar algo destrutivo achando que tava ajudando?*

O Agent Cage é a coleira invisível pra esse medo. Ele fica de olho no que o agente faz *dentro do próprio kernel do Linux* — não confia no que o agente promete, vê o que ele realmente executa — e aplica as regras que você definiu. Se ele tentar ler um arquivo de credencial, conectar num domínio não autorizado, ou rodar um shell suspeito, o Agent Cage mata o processo na hora. Sem sandbox pesado, sem copiar seu projeto pra nuvem, sem perder a velocidade de trabalhar local.

## ⚠️ Antes de instalar: isso roda em Linux, ponto

Esta é uma limitação física, não uma escolha de roadmap adiável: o Agent Cage usa **eBPF**, uma tecnologia do kernel Linux. Não existe em Windows nativo, não existe em macOS. **WSL2 não é suportado** — testamos, o subsistema de kernel dele não expõe a superfície de eBPF necessária de forma confiável (correlação de PID entre namespace quebra silenciosamente). Se você está em Windows ou Mac, veja a seção [Windows e macOS](#windows-e-macos-o-que-seria-necessário) mais abaixo antes de tentar instalar.

## Instalação

### Opção recomendada: compilação direta via Cargo

O SyscallCage é escrito em Rust e eBPF (utilizando a biblioteca Aya). Você pode compilar o binário do userspace e do eBPF diretamente no seu ambiente de desenvolvimento.

```bash
git clone https://github.com/rodrigoffreir3/syscallcage.git
cd syscallcage

# 1. Compile o bytecode do eBPF (exige Rust Nightly e bpf-linker)
cargo +nightly build --package syscallcage-ebpf --target bpfel-unknown-none -Z build-std=core --release

# 2. Compile o binário do userspace
cargo build --release
```

Requisitos para compilar:
- Rust (Stable e Nightly toolchains instalados via rustup).
- `bpf-linker` instalado (`cargo install bpf-linker`).

### Por que não Docker

Decisão deliberada, não esquecimento: o SyscallCage precisa anexar eBPF no kernel do **host** e enxergar o PID do processo monitorado no namespace **real** da máquina. Rodar isso dentro de um container exigiria `--pid=host` e `--privileged` — o que anula praticamente todo o isolamento que Docker existe para oferecer, e reintroduz exatamente a classe de bug de mismatch de namespace que originalmente nos custou horas de debug no WSL2. Para esta ferramenta especificamente, dockerizar pioraria a segurança em vez de simplificar a instalação.

## Uso

```bash
sudo ./syscallcage --pid <PID-do-agente> --policy configs/exemplo.yaml
```

Hoje o binário exige `sudo` completo para anexar os programas eBPF. Isso é conhecido e não é o estado final desejado — ver [Roadmap](#roadmap) sobre restringir para capabilities específicas (`CAP_BPF`, `CAP_PERFMON`) em vez de root irrestrito.

```yaml
mode: enforce  # ou "monitor", pra só observar sem matar nada

filesystem:
  allow_read:
    - "/home/voce/seu-projeto/**"
  deny_always:
    - "**/.env"
    - "**/.ssh/**"

network:
  allow_domains:
    - "api.anthropic.com"
    - "github.com"
  deny_all_else: true

syscalls:
  deny:
    - "execve:/bin/sh"
```

Zero trust de verdade: o que não foi explicitamente permitido é negado por padrão. `deny_always` sempre vence qualquer `allow`. Não tem exceção escondida, não tem modo debug que desliga a segurança sem querer.

## Como funciona (pra quem quer saber)

Um daemon eBPF observa as syscalls do processo do agente (e de qualquer processo filho que ele criar) em tempo real: abertura de arquivo, execução de comando, conexão de rede. Cada evento é comparado contra a política declarativa acima. Se a política é violada, o processo é encerrado (`SIGKILL`) ou apenas registrado, dependendo do modo escolhido.

## Como funciona

O SyscallCage suporta dois modos de operação automáticos:
1. **Modo Síncrono (BPF LSM - Recomendado):** Se o kernel suportar BPF LSM (detectado via `/sys/kernel/security/lsm`), as requisições de filesystem e execve são interceptadas e negadas de forma síncrona diretamente no kernel, retornando `-EACCES` nativamente para o processo.
2. **Modo Reativo (Tracepoints + Kprobes):** Caso o kernel não possua suporte ao LSM, ele realiza o fallback automático para o modo clássico, onde eventos de violação são monitorados e encerram o processo com `SIGKILL` reativamente.

A rede e resolução DNS continuam reativas em ambos os modos.

## Limitações conhecidas (documentadas de propósito)

- Resolução de domínio via DNS assume resposta comprimida (padrão da imensa maioria dos servidores). Nome de domínio com mais de 10 níveis de subdomínio não é suportado no parsing atual.
- IPv6 é bloqueado por padrão (fail-closed), não tem suporte funcional completo ainda.
- Em caso de morte abrupta via `kill -9` no próprio `syscallcage`, o kernel Linux fecha automaticamente os descritores e descarrega todos os hooks eBPF instalados de forma limpa, não deixando ganchos órfãos no sistema.

## Windows e macOS: o que seria necessário

Sabemos que a necessidade de uma coleira de segurança para agente de IA é, se algo, **maior** para quem não é profissional de TI — o dev de infra já costuma ter instinto e ferramenta própria de contenção; quem não é técnico confia no agente por padrão, sem saber que existe alternativa. Isso nos importa, e vale registrar o caminho real, não só dizer "não dá":

**Windows**: não existe eBPF nativo, mas existe **ETW (Event Tracing for Windows)**, a superfície de observação de kernel que antivírus e EDR comerciais usam no Windows. Portar a lógica de política (que já vive isolada em Rust puro, sem eBPF, nos pacotes `policy` e `enforcer`) para consumir eventos ETW em vez de ring buffer eBPF é trabalho real de engenharia, mas não é reescrita do zero — é escrever um novo monitor para Windows, mantendo o resto do produto.

**macOS**: o equivalente seria o framework **EndpointSecurity** da Apple, que exige entitlement especial assinado pela Apple para monitorar outros processos — mais burocrático de distribuir que Linux ou Windows, mas tecnicamente viável.

Nenhuns dos dois está no roadmap imediato — cada um é essencialmente um novo backend de observação, não um ajuste. Se isso te interessa como contribuidor, é exatamente o tipo de contribuição que a arquitetura atual (política e enforcement já desacoplados do monitor eBPF) foi desenhada para acomodar.

## Roadmap

- [ ] Capabilities específicas (`CAP_BPF`, `CAP_PERFMON`) em vez de exigir root completo.
- [ ] Backend de monitor para Windows via ETW.
- [ ] Backend de monitor para macOS via EndpointSecurity.

## Licença

MPL 2.0 — modifique, use comercialmente, distribua. A única exigência é que mudanças nos arquivos deste projeto continuem abertas sob a mesma licença; o resto do seu projeto pode ser proprietário sem problema.

## Por que existe

Ferramenta nascida da mesma linha de pesquisa do [Imunno System](https://github.com/SEU-USUARIO) (EDR baseado em eBPF, patente INPI), aplicando detecção comportamental de kernel a um problema novo: confiar em agente de IA autônomo sem abrir mão de segurança.
