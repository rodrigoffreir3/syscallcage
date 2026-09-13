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

> [!TIP]
> **Acesso direto via `sudo`:**
> Por padrão de segurança no Linux, o comando `sudo` utiliza um `PATH` próprio (`secure_path`) que ignora diretórios de usuário como `~/.local/bin`. Para que você possa rodar `sudo syscallcage` direto de qualquer lugar sem o erro `command not found`, crie um link simbólico no sistema:
> ```bash
> sudo ln -sf ~/.local/bin/syscallcage /usr/local/bin/syscallcage
> sudo ln -sf ~/.local/bin/syscallcage-ebpf /usr/local/bin/syscallcage-ebpf
> ```

### Ativando o BPF LSM no Linux (Modo Síncrono Preventivo)

O SyscallCage funciona imediatamente em modo reativo (abate o processo na hora caso ocorra violação). Para ativar o bloqueio **síncrono e preventivo** (onde a chamada do agente é barrada pelo kernel *antes* de executar), ative o módulo `bpf` no boot da sua distribuição Linux:

1. Abra `/etc/default/grub` como administrador:
   ```bash
   sudo nano /etc/default/grub
   ```
2. Adicione `lsm=landlock,lockdown,yama,integrity,apparmor,bpf` na variável `GRUB_CMDLINE_LINUX_DEFAULT`:
   ```bash
   GRUB_CMDLINE_LINUX_DEFAULT="quiet splash lsm=landlock,lockdown,yama,integrity,apparmor,bpf"
   ```
3. Atualize o GRUB e reinicie o computador:
   ```bash
   sudo update-grub
   sudo reboot
   ```
4. Ao reiniciar, confirme com `syscallcage doctor`:
   ```text
   ✓ BPF LSM disponível — modo síncrono (recomendado) será usado.
   ```

*(A URL do instalador acima usa o GitHub diretamente — é a versão honesta de "funciona hoje". Um domínio próprio é melhoria futura documentada no roadmap.)*

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

## Como encontrar o processo (PID) da IA e vinculá-lo

O **PID** (*Process Identifier*) é o identificador numérico único que o Linux atribui a qualquer programa em execução. Como agentes e modelos de IA podem rodar de diferentes formas (extensões de IDE, ferramentas de linha de comando ou servidores locais), aqui estão as formas mais práticas de localizá-los e colocá-los sob a vigilância do SyscallCage:

### 1. Descobrindo qual é o processo do seu agente

Dependendo de como você usa IA no seu fluxo de trabalho:

- **Assistentes e extensões de IDE (Cursor, Antigravity, VS Code, Windsurf):**  
  Essas ferramentas operam criando processos de backend em segundo plano, normalmente chamados de *Language Servers* ou servidores de extensão.
  - Para localizar:
    ```bash
    pgrep -fl language_server
    ```
    ou procurando por processos de servidor da IDE:
    ```bash
    pgrep -fl cursor
    pgrep -fl code
    ```

- **Agentes de terminal / CLI (Claude Code, Aider, OpenHands, Goose):**  
  Executam como comandos diretos ou scripts Node/Python.
  - Para localizar:
    ```bash
    pgrep -fl claude
    pgrep -fl aider
    pgrep -fl python
    ```

- **Servidores locais de modelos (Ollama, LocalAI, vLLM):**  
  - Para localizar:
    ```bash
    pgrep -fl ollama
    ```

> [!TIP]
> O parâmetro `-fl` no `pgrep` lista o **PID** junto com o **nome completo da linha de comando** que iniciou o processo, facilitando confirmar se você está selecionando o agente correto.

Se preferir ver tudo graficamente no terminal, você também pode abrir o `htop` (ou `btop`), pressionar `F3` (ou `/`), digitar o nome do processo e olhar o número na coluna **PID**.

### 2. Vinculando o processo ao SyscallCage

Com o PID identificado, você pode vinculá-lo de duas formas:

- **Informando o PID diretamente:**
  ```bash
  sudo syscallcage --pid 12345 --policy minha-politica.yaml
  ```

- **Vinculando automaticamente em um comando só:**  
  Se você já sabe o nome do processo e quer engatar a proteção direto sem precisar copiar e colar o número:
  ```bash
  sudo syscallcage --pid $(pgrep -f language_server | head -n 1) --policy minha-politica.yaml
  ```
  *(O trecho `$(pgrep -f ... | head -n 1)` resolve o PID em tempo real e o repassa como argumento).*

Pronto! A partir desse momento, todas as chamadas de sistema (leitura/escrita de arquivos, comandos e acessos) feitas pelo processo do agente são monitoradas e contidas pelo kernel.

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

## Cenários Possíveis de Dúvidas / Ajustes de Ambiente

Nem todo usuário vai passar por essas situações, mas caso você encontre algum desses cenários no seu ambiente, as soluções já estão mapeadas e prontas:

### 1. `sudo: 'syscallcage': command not found`
- **Por que acontece:** O `sudo` por padrão de segurança no Linux limpa as variáveis de ambiente (`secure_path`) e não busca executáveis em diretórios pessoais como `~/.local/bin`.
- **Solução:** Crie um link simbólico dos binários para um diretório do sistema:
  ```bash
  sudo ln -sf ~/.local/bin/syscallcage /usr/local/bin/syscallcage
  sudo ln -sf ~/.local/bin/syscallcage-ebpf /usr/local/bin/syscallcage-ebpf
  ```

### 2. `syscallcage doctor` avisa que o BPF LSM está indisponível (Fallback Reativo)
- **Por que acontece:** Distribuições modernas (como Ubuntu 22.04/24.04+) já vêm com o kernel compilado com suporte a BPF LSM (`CONFIG_BPF_LSM=y`), mas o módulo `bpf` precisa ser explicitamente listado na ordem de inicialização do boot no GRUB para habilitar a contenção preventiva síncrona.
- **Solução:**
  1. No arquivo `/etc/default/grub`, adicione `lsm=landlock,lockdown,yama,integrity,apparmor,bpf` na variável `GRUB_CMDLINE_LINUX_DEFAULT`:
     ```bash
     GRUB_CMDLINE_LINUX_DEFAULT="quiet splash lsm=landlock,lockdown,yama,integrity,apparmor,bpf"
     ```
  2. Atualize o GRUB e reinicie o computador:
     ```bash
     sudo update-grub
     sudo reboot
     ```
  3. Confirme o carregamento com `cat /sys/kernel/security/lsm` e `syscallcage doctor`.

### 3. "Operation inhibited by user session" ao tentar reiniciar (`systemd-inhibit`)
- **Por que acontece:** Se a sua interface gráfica de desktop (GNOME/KDE) estiver com aplicativos abertos, o `systemd` pode inibir o comando de reinicialização para evitar perda de dados.
- **Solução:** Para reiniciar ignorando travas da sessão de usuário:
  ```bash
  sudo systemctl reboot -i
  ```

### 4. Regras em `syscalls.deny` caindo para modo reativo
- **Por que acontece:** O compilador síncrono do BPF LSM atua nos ganchos de execução e espera que as regras de syscall sigam o formato com o prefixo da operação (ex: `execve:/bin/sh`, `execve:/bin/bash`). Padrões genéricos livres fora desse formato fazem o SyscallCage alternar de forma segura para o modo reativo.
- **Solução:** Em políticas em modo síncrono (`enforce`), declare chamadas proibidas no formato `execve:<caminho>`.

### 5. Finalização de Processos e o Modo `watch`
- **Como funciona:** O `watch` supervisiona a execução do seu agente. Quando o comando finaliza com sucesso (`código 0`) ou encerra por erro/bloqueio, a supervisão é concluída imediatamente sem loops. Caso você queira que o supervisor reinicie comandos que falhem por instabilidade de rede ou falhas normais, basta usar a flag `--max-restarts <N>`.

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
