# SyscallCage (SCC)

**A coleira que faz sua IA trabalhar sozinha, no seu computador, sem medo do que ela pode fazer.**

> 🔭 **Página oficial e documentação completa:** [rodrigofreire.pages.dev/syscallcage](https://rodrigofreire.pages.dev/syscallcage)

**O SCC atualmente é um MVP em constante validação e evolução. Serei imensamente grato se quiser ajudar no desenvolvimento do MVP com comentário construtivo e direcional. Por favor, mantenha a educação e o decoro. Os comentários podem ser feitos na pagina oficial do projeto (link acima) na área de comentários. Grato pela sua compreensão e apoio.**

## 🚀 Chegando em breve

O SyscallCage está em evolução ativa. Já funciona hoje, de ponta a ponta, em Linux — e o roadmap público já garante que você não vai ficar esperando no escuro:

- **Bloqueio síncrono de rede** — hoje já bloqueamos filesystem e execução de comando *antes* deles acontecerem via BPF LSM; rede é o próximo alvo dessa mesma technologia.
- **Windows (via ETW)** e **macOS (via EndpointSecurity)** — a mesma filosofia de vigilância no kernel, adaptada pra quem não vive em Linux.
- **Capabilities refinadas** (`CAP_BPF`, `CAP_PERFMON`) no lugar de root completo — menos privilégio, mesma proteção.

Nenhum desses itens é promessa vaga: cada um já tem desenho técnico definido. Comece a usar agora — o que funciona hoje já resolve o problema real, e o que vem por aí só vai deixar ainda mais forte.

## O problema

Você usa um agente de IA (Claude Code, Cursor, ou parecido) que edita arquivos e roda comandos sozinho, sem você aprovar cada passo. É rápido e poderoso — mas sempre fica aquele desconforto: *e se ele ler minha senha sem eu perceber? E se mandar alguma coisa pra internet sem eu autorizar? E se rodar um comando perigoso achando que estava ajudando?*

## O que o SyscallCage faz

Ele fica de olho no que o agente **realmente faz** no seu computador — não no que ele promete fazer. Você define regras simples (que pastas ele pode ler, que sites pode acessar, o que nunca pode rodar), e o SyscallCage garante isso na hora, direto no kernel do Linux, sem depender do agente cooperar ou avisar antes.

Se o kernel do seu sistema suportar (a maioria dos Linux modernos suporta), a barreira age **antes** da violação completar — o comando nem chega a rodar. Onde isso não é possível, ele age imediatamente depois, encerrando o processo com a mesma agilidade.

## Onde ele atua

Na camada mais fundamental que existe entre um programa e o computador: o kernel. Isso significa que ele enxerga qualquer coisa que qualquer processo faça de verdade — abrir arquivo, executar comando, conectar na rede — sem depender do agente ter uma função especial de "avisar antes" (que a maioria nem tem, e que pode ser ignorada ou falhar).

## Quando ele age

Toda vez, sem exceção, enquanto o processo protegido estiver vivo.

## Por que ele é diferente

A abordagem mais comum pra esse problema hoje é colocar o agente inteiro dentro de um ambiente isolado — um computador dentro do computador. Funciona, mas custa: é pesado, lento de configurar, e você perde a conveniência de trabalhar direto na sua pasta de projeto real.

O SyscallCage não isola nada. Ele deixa o agente trabalhar exatamente onde já estava — e observa, no nível mais fundo do sistema, se algo passa da linha. É a diferença entre trancar alguém numa sala vazia e ter um segurança de confiança de olho na sala de sempre. Você não perde velocidade nem muda seu fluxo de trabalho pra ganhar segurança.

> ⚖️ **Quer entender como isso se compara com Docker (Seccomp), AppArmor, Landlock e Falco?** Leia o nosso guia detalhado de [Alternativas e Trade-offs](docs/alternatives.md).

## Como instalar

Instalação em um comando só (baixa o binário já compilado da release, checksum verificado — nenhuma compilação acontece na sua máquina):

```bash
curl -fsSL https://raw.githubusercontent.com/rodrigoffreir3/syscallcage/main/install.sh | sh
```

Isso instala em `~/.local/bin`, sem exigir `sudo` para o passo de instalação em si. Ao final, confira o ambiente com `syscallcage doctor`.

*(A URL acima usa o GitHub diretamente — é a versão honesta de "funciona hoje". Um domínio próprio é melhoria futura documentada no roadmap.)*

### Instalando a partir do código-fonte

```bash
git clone https://github.com/rodrigoffreir3/syscallcage
cd syscallcage
cargo build --release --workspace
```

Requisitos: Rust (stable + nightly via rustup), `bpf-linker` (`cargo install bpf-linker`), `clang`/`llvm`.

## Como usar

Escreva um arquivo pequeno dizendo o que é permitido:

```yaml
mode: enforce

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
```

Depois, aponte o SyscallCage pro processo do seu agente:

```bash
sudo ./target/release/syscallcage --pid <PID-do-agente> --policy sua-politica.yaml
```

Pronto. Ele vigia até o processo terminar ou você mandar parar.

### Não sabe o que colocar nas regras?

Deixe o SyscallCage descobrir sozinho, observando uma sessão real:

```bash
sudo ./target/release/syscallcage --pid <PID> --policy configs/exemplo-monitor-mode.yaml --log-file sessao.jsonl
# deixe o agente trabalhar normalmente...
./target/release/syscallcage generate-policy --from-log sessao.jsonl --output minha-politica.yaml
```

Ele nunca sugere liberar arquivo de credencial ou comando perigoso, mesmo que apareça na sessão observada — isso fica de fora, sempre.

### O que você vê quando algo é bloqueado

Quando o SyscallCage barra uma ação proibida (como uma tentativa de leitura a um arquivo `.env` ou chave privada), ele emite um log estruturado em formato JSON identificando a ação interceptada:

```json
{"timestamp":"2026-07-24T17:00:00Z","level":"fatal","component":"enforcer","message":"violação de política crítica: encerrando processo","pid":1234,"event_type":"open","target":"/home/user/project/.env","action":"kill"}
```

No modo `watch`, o supervisor intercepta a morte do processo e registra a interrupção da supervisão no log:

```json
{"timestamp":"2026-07-24T17:00:00Z","level":"fatal","component":"watch","message":"agente encerrado por violação de política -- supervisão interrompida, requer intervenção humana"}
```

## Entendendo o comando, pedaço por pedaço

Se você nunca usou terminal antes, um comando como esse pode parecer papagaio grego:

```bash
sudo ./target/release/syscallcage --pid <PID> --policy sua-politica.yaml
```

Vamos abrir ele. Cada parte tem um motivo:

- **`sudo`** — "rode isso com permissão de administrador". O SyscallCage precisa desse nível de acesso porque ele vigia o sistema operacional por dentro, não só o app comum. É o mesmo `sudo` que você usa pra instalar qualquer programa no Linux.
- **`./target/release/syscallcage`** — o caminho até o programa que você acabou de compilar. É literalmente "onde o SyscallCage mora no seu computador agora".
- **`--pid <PID>`** — "qual processo eu devo vigiar". PID é o número de identificação que o Linux dá a cada programa rodando (tipo um RG temporário). Você descobre o PID do seu agente de IA com o comando `pgrep nome-do-programa` ou olhando no gerenciador de processos.
- **`--policy sua-politica.yaml`** — "onde estão as regras que eu devo seguir". É o arquivo de texto (mostrado acima) que diz o que é permitido e o que não é.

Se um dia você precisar pesquisar sobre isso no Google, já sabe o nome de cada peça: "PID", "sudo", "flag de linha de comando". Isso ajuda muito mais que decorar o comando inteiro sem entender.

## O modo `watch` — a versão sem precisar descobrir PID

```bash
sudo syscallcage watch --policy minha-politica.yaml -- claude-code --seus-argumentos
```

Esse modo elimina o passo mais chato (achar o PID manualmente): o SyscallCage cria o processo do agente com `fork`+`exec`, sabendo o PID no instante em que ele nasce, e reinicia automaticamente em caso de crash normal — nunca em caso de violação de política, que sempre exige intervenção humana. Se o `syscallcage` for morto, o agente recebe `SIGTERM` junto (via `PR_SET_PDEATHSIG`): "parado" é sempre preferível a "rodando sem proteção". Explicando cada parte nova:

- **`watch`** — diz pro SyscallCage "não é pra vigiar um processo que já existe, é pra você mesmo criar e tomar conta dele desde o nascimento".
- **`--policy minha-politica.yaml`** — igual antes, o arquivo de regras.
- **`--`** (dois hífens sozinhos) — isso é uma convenção comum em programas de linha de comando. Significa "tudo que vier depois daqui não é mais opção do SyscallCage, é o comando que você quer que ele rode e proteja". Sem esse separador, o programa não saberia onde terminam as opções do SyscallCage e começa o comando do agente.
- **`claude-code --seus-argumentos`** — o comando que você normalmente usaria pra rodar seu agente, exatamente do jeito que você já usa hoje, só que precedido pelo SyscallCage.

Nesse modo, você nunca precisa descobrir PID nenhum — o SyscallCage já nasce sabendo, porque é ele quem liga o agente.

## Importante saber

- **Funciona nativamente em Linux e agora em Windows via WSL2** (com as devidas configurações de kernel e BPF LSM).
- **Pede permissão de administrador (`sudo`)** pra anexar a vigilância no nível de kernel.
- Limitações atuais estão documentadas com honestidade na [página oficial](https://rodrigofreire.pages.dev/syscallcage) — sem promessa exagerada.

## Suporte a Windows (WSL2)

O Windows não possui as interfaces do kernel Linux, mas é possível rodar o SyscallCage em modo síncrono (preventivo) dentro do **WSL2**, compilando um kernel próprio com `CONFIG_BPF_LSM` habilitado — o kernel padrão distribuído pela Microsoft no WSL2 vem com essa opção desligada.

Passo a passo completo, reprodutível e auditável (você compila o próprio kernel a partir da fonte oficial da Microsoft — nunca baixe um binário de kernel pronto de terceiros, é risco de segurança real, não excesso de cautela): **[docs/WSL_BPF_LSM_Decision.md](docs/WSL_BPF_LSM_Decision.md)**.

Esse documento também registra o histórico técnico completo até chegar nesse suporte funcionando — incluindo um bug real do verifier do kernel que apareceu no caminho e como foi corrigido de verdade, não só contornado.

## Licença

MPL 2.0 — use, modifique, use até comercialmente. A única exigência é que mudanças nos arquivos deste projeto continuem abertas sob a mesma licença.

## Por que existe

Nasceu da mesma linha de pesquisa do Imunno System, um antivírus de comportamento para servidores Linux com patente registrada no Brasil (INPI). O SyscallCage aplica a mesma ideia — observar comportamento real, nunca confiar em promessa — a um problema novo: deixar IA trabalhar sozinha sem abrir mão de segurança.
