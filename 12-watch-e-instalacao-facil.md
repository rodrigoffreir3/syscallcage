# SPEC GT-12 — Watch Supervisor + Instalação de Um Comando (ciclo de fechamento pré-divulgação)

## Princípios (repetido de propósito em todo spec, sem exceção)

1. **Simplicidade**: a solução mais simples que atende ao requisito é a
   correta.
2. **Legibilidade**: nomes descrevem intenção, comentário explica o
   *porquê*.
3. **Manutenibilidade** de curto, médio e longo prazo — código pensado
   para ser lido e modificado sem reconstruir raciocínio do zero.
4. **Complexidade justificada**: só entra abstração nova quando o simples
   comprovadamente não resolve. Comentar explicitamente quando isso
   acontecer.
5. **Zero trust**: o que não foi explicitamente permitido é negado por
   padrão, sempre — inclusive nas próprias decisões de infraestrutura
   deste spec (ex: checksum de instalação nunca é "melhor esforço").
6. **Testes em tudo, sempre**: nenhuma função pública sem teste. O que
   depende de kernel real ou processo real é testado manualmente com
   procedimento explícito.
7. **Log sempre, nunca silêncio**: todo erro, toda decisão, todo estado
   inesperado gera log estruturado.
8. **Nunca quebrar o que já existe**: a suite E2E completa já validada
   (5 cenários) e o modo `--pid` atual continuam funcionando
   identicamente após este spec. Nada aqui é substituição — é adição.

## Contexto: por que estas duas coisas viram um spec só

Antes de divulgar o SyscallCage publicamente (HN, r/rust, r/netsec), duas
lacunas concretas precisam fechar — cada uma mina a primeira impressão de
um jeito diferente:

- **Sem `watch`**: qualquer dev técnico lendo o projeto pergunta "e se o
  processo cair?" e não tem resposta boa. Hoje o SyscallCage é passivo
  (aponta pra um PID que já existe) — não sobrevive a restart do agente.
- **Sem instalação fácil**: quem só quer testar rapidamente esbarra em
  "compile com Rust nightly + bpf-linker + clang" e desiste antes de
  rodar. Isso mata o feedback que mais importa (gente de fora usando de
  verdade), justo no momento em que ele seria mais valioso.

O pipeline de build multi-arquitetura **já está validado** — a tag
`v0.1.0` gerou release limpo para `x86_64` e `aarch64` no GitHub Actions,
com checksum publicado. O que falta não é o pipeline, é: (a) o modo
`watch` em si, e (b) o `install.sh` estar hospedado e testado de ponta a
ponta numa máquina limpa, além de um comando de diagnóstico pós-instalação.

---

## PARTE 1 — Modo `watch` (supervisor nativo)

### O problema que resolve

1. **Restart do agente** muda o PID; ninguém reanexa o SyscallCage
   automaticamente — o agente roda **sem proteção** até alguém notar.
2. **Janela de corrida na inicialização**: mesmo hoje, entre iniciar o
   agente por fora e apontar o SyscallCage pra ele, existe intervalo real
   sem vigilância.

`watch` elimina os dois: o SyscallCage passa a **criar** o processo do
agente via `fork()` + `exec()`, conhecendo o PID no instante exato em que
nasce, e reiniciando automaticamente quando fizer sentido.

### Decisão de arquitetura — `PR_SET_PDEATHSIG`, obrigatório, não opcional

Logo após o `fork()`, **antes** do `exec()`, o processo filho chama
`prctl(PR_SET_PDEATHSIG, SIGTERM)`: "se meu pai morrer, me mande SIGTERM
automaticamente".

**Por que é obrigatório**: sem isso, se o SyscallCage travar ou for morto
(`kill -9`, mesmo cenário do GT-03/GT-05), o agente vira órfão e continua
rodando **sem vigilância nenhuma**, silenciosamente. Zero trust exige que
ausência de supervisor resulte em parar o supervisionado, nunca em deixá-lo
correr solto. Isto é mudança real de postura: hoje, matar o SyscallCage
não afeta o agente; no modo `watch`, matar o supervisor também encerra o
agente de propósito — "parado" é sempre preferível a "rodando sem proteção".

```rust
#[cfg(target_os = "linux")]
fn set_parent_death_signal() -> Result<(), std::io::Error> {
    use libc::{prctl, PR_SET_PDEATHSIG, SIGTERM};
    let ret = unsafe { prctl(PR_SET_PDEATHSIG, SIGTERM) };
    if ret != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}
```

### Ordem exata de operações (não deixar em aberto)

1. Carrega e valida a política (`Policy::load`) **antes** do fork — falhar
   aqui aborta tudo, sem sentido criar processo filho pra descobrir depois
   que a política é inválida.
2. `fork()`.
3. No **filho**: `set_parent_death_signal()` primeiro, depois `execvp()`
   do comando do agente. Se `execvp` retornar, é falha (comando não
   encontrado/sem permissão) — o filho morre imediatamente (`exit(127)`),
   sem herdar estado do SyscallCage.
4. No **pai**: assim que `fork()` retorna o PID do filho, monta o
   `Monitor` com esse PID e anexa os hooks eBPF **antes** de qualquer
   `waitpid`. Anexar depois de esperar o filho terminar seria tarde
   demais.

```rust
// syscallcage/src/watch.rs -- módulo novo

use nix::unistd::{fork, ForkResult, execvp};
use nix::sys::wait::{waitpid, WaitStatus};
use std::ffi::CString;

pub struct WatchConfig {
    pub policy_path: std::path::PathBuf,
    pub command: Vec<String>,
    pub max_restarts: Option<u32>,  // None = restart infinito (default)
}

pub fn run(config: WatchConfig) -> Result<(), WatchError> {
    let policy = Policy::load(&config.policy_path)?;
    let mut restart_count = 0u32;

    loop {
        if let Some(max) = config.max_restarts {
            if restart_count >= max {
                logging::fatal("watch", "número máximo de reinícios atingido, encerrando supervisão");
                return Err(WatchError::MaxRestartsExceeded);
            }
        }

        match unsafe { fork() }? {
            ForkResult::Child => {
                set_parent_death_signal()?;
                let c_command: Vec<CString> = config.command.iter()
                    .map(|s| CString::new(s.as_str()).unwrap())
                    .collect();
                let _ = execvp(&c_command[0], &c_command);
                std::process::exit(127); // só chega aqui se execvp falhou
            }
            ForkResult::Parent { child } => {
                let pid = child.as_raw() as u32;
                logging::info("watch", &format!("agente iniciado sob supervisão, pid={}", pid));

                let kill_reason: std::sync::Arc<std::sync::Mutex<Option<KillReason>>> =
                    Default::default();
                let kr_clone = kill_reason.clone();

                let monitor = Monitor::new(pid, &policy, move |evt| {
                    // handler já existente; se o enforcer decidir matar
                    // por violação, grava o motivo aqui antes de agir
                })?;
                monitor.start()?; // bloqueia, igual ao modo --pid hoje

                match waitpid(child, None)? {
                    WaitStatus::Signaled(_, sig, _) => {
                        if *kill_reason.lock().unwrap() == Some(KillReason::PolicyViolation) {
                            logging::fatal("watch", "agente encerrado por violação de política -- supervisão interrompida, requer intervenção humana");
                            return Err(WatchError::PolicyViolationHalt);
                        }
                        logging::log(logging::Entry {
                            level: "warn", component: "watch",
                            message: &format!("agente encerrado pelo sinal {:?}, reiniciando", sig),
                            pid: Some(pid), ..Default::default()
                        });
                    }
                    WaitStatus::Exited(_, code) => {
                        logging::log(logging::Entry {
                            level: "warn", component: "watch",
                            message: &format!("agente encerrou com código {}, reiniciando", code),
                            pid: Some(pid), ..Default::default()
                        });
                    }
                    _ => {}
                }
                restart_count += 1;
            }
        }
    }
}
```

### Detalhe crítico: violação de política nunca gera restart automático

Se o processo morreu porque violou a política (ex: tentou ler `.env`),
reiniciar automaticamente faria o agente tentar de novo — possível loop
de recursos, ou pior, superfície de retry explorável em cenário
timing-dependente.

**Correção obrigatória no `Enforcer`**: expor **por que** matou, não só
executar silenciosamente.

```rust
// enforcer/mod.rs -- extensão
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KillReason {
    PolicyViolation,
}
```

O `handler` passado ao `Monitor`, no modo `watch`, seta essa informação
(via `Arc<Mutex<Option<KillReason>>>` ou canal) quando uma violação
resulta em kill. O loop de `watch` checa isso antes de decidir reiniciar:
**violação → para a supervisão, log fatal, exige intervenção humana.
Crash normal → reinicia.**

### CLI

```rust
// main.rs -- adiciona ao enum Command existente, sem tocar no resto
Command::Watch {
    #[arg(long)]
    policy: PathBuf,
    #[arg(long)]
    max_restarts: Option<u32>,
    #[arg(last = true)]
    command: Vec<String>,
},
```

```bash
sudo syscallcage watch --policy minha-politica.yaml -- claude-code --seus-argumentos
```

### Testes obrigatórios da Parte 1

- `set_parent_death_signal()` testável isolado (chama, confirma sucesso
  de `prctl` — não precisa simular morte real do pai para validar a
  chamada em si).
- Teste manual: `watch` com script que termina sozinho após N segundos →
  confirma restart automático, contador incrementando no log.
- Teste manual: `kill -9` no processo `syscallcage` pai enquanto o filho
  roda → confirma que o filho recebe `SIGTERM` (prova real de
  `PR_SET_PDEATHSIG` funcionando, não só código que parece certo).
- Teste manual: política restritiva, agente viola (ex: lê `.env`) →
  confirma que **não** reinicia, loga `fatal`, encerra a supervisão.
- Teste manual: `--max-restarts 3`, provoca 3 crashes normais seguidos →
  quarto crash não reinicia, programa encerra com erro.

---

## PARTE 2 — Instalação de um comando (fechamento do que já existe)

### O que já está pronto (não refazer)

- Workflow `.github/workflows/release.yml` — validado, gerou `v0.1.0`
  limpo para `x86_64-unknown-linux-gnu` e `aarch64-unknown-linux-gnu`,
  com checksum `.sha256` publicado para os dois.
- `.cargo/config.toml` com linker cross para `aarch64` corrigido e
  confirmado funcionando.
- `install.sh` já escrito (spec GT-09), com detecção de SO/arquitetura,
  verificação de checksum obrigatória (nunca "melhor esforço"), instalação
  em `~/.local/bin` sem exigir `sudo` para o passo de instalação em si.
- `syscallcage doctor` já implementado (checa binário, kernel, BPF LSM,
  localização do companion eBPF, privilégio).

### O que falta de verdade (o único trabalho real desta parte)

1. **Domínio ou path estável para hospedar `install.sh`.** Hoje o
   `install.sh` existe no repositório, mas o comando de instalação
   documentado (`curl -fsSL https://syscallcage.dev/install.sh | sh`)
   aponta para um domínio que ainda não existe. **Decisão**: até o
   domínio próprio existir, usar a URL raw do GitHub como destino real e
   documentar exatamente essa URL, nunca uma que não resolve:
   ```bash
   curl -fsSL https://raw.githubusercontent.com/rodrigoffreir3/syscallcage/main/install.sh | sh
   ```
   Isto não é solução definitiva, é a versão **honesta** de "funciona
   hoje" — o domínio próprio vira melhoria futura documentada no roadmap,
   não uma URL fictícia no README atual.

2. **Teste de ponta a ponta em máquina limpa**, algo que nunca foi feito
   até agora com o `install.sh` real (só foi escrito e revisado, não
   executado em ambiente sem Rust/clang pré-instalados):
   ```bash
   # Em VM/container limpo, SEM Rust, SEM clang, SEM bpf-linker:
   curl -fsSL <url-do-install.sh> | sh
   syscallcage doctor
   ```
   Critério de sucesso: do `curl` até `doctor` reportando ambiente pronto,
   sem nenhum passo manual, em menos de um minuto (o binário já vem
   compilado da release — não deveria haver compilação nenhuma acontecendo
   na máquina do usuário final).

3. **Atualizar `install.sh` para instalar também o modo `watch`** — como
   é o mesmo binário (`syscallcage` ganha um subcomando novo, não um
   binário separado), **nenhuma mudança é necessária no script em si**.
   Isto é só confirmação: rodar o teste do item 2 numa versão do binário
   que já inclui `watch` (ou seja, fazer a Parte 1 antes de validar a
   Parte 2 pela última vez).

### Testes obrigatórios da Parte 2

- `install.sh` rodado em ambiente limpo (VM ou container Docker apenas
  para este teste específico — não para o produto em si, que continua
  não sendo dockerizado) instala com sucesso e sem passo manual.
- Checksum incorreto proposital (edita o `.sha256` publicado ou simula
  download corrompido) faz o script abortar com erro claro, nunca
  "seguir mesmo assim".
- `syscallcage doctor` roda sem privilégio elevado e reporta os 5 itens
  esperados (binário, kernel, BPF LSM, companion eBPF, privilégio).

---

## Ordem de implementação (sequencial, cada etapa valida a anterior)

1. `set_parent_death_signal()` isolado e testado.
2. Extensão `KillReason` no `Enforcer` — sem isso, o passo 3 não pode
   diferenciar violação de crash normal.
3. Módulo `watch.rs` com loop fork/exec/waitpid, ainda sem tratar
   `KillReason` (assume sempre reinício).
4. Integra `KillReason` no loop — só reinicia se não foi violação.
5. Subcomando CLI `watch`.
6. Suite de testes manuais da Parte 1, em kernel real (Lubuntu ou a VM
   VirtualBox já validada com modo Sync confirmado).
7. Recompila release incluindo `watch`, gera nova tag (ex: `v0.2.0`).
8. Testa `install.sh` de ponta a ponta em máquina limpa (Parte 2, item 2),
   usando a release nova.
9. Atualiza README com a URL real de instalação (raw GitHub, não domínio
   fictício) e menciona `watch` como disponível, não mais "chegando em
   breve".

## Critério de sucesso geral deste spec

- [ ] `sudo syscallcage watch --policy x.yaml -- <comando>` protege o
      agente desde o primeiro milissegundo, sem PID manual.
- [ ] Crash normal reinicia automaticamente; violação de política nunca
      reinicia sozinha.
- [ ] `kill -9` no `syscallcage` pai propaga `SIGTERM` pro agente filho.
- [ ] Modo `--pid` existente permanece 100% funcional, sem regressão.
- [ ] `curl | sh` funciona do zero em máquina limpa, sem compilação local,
      em menos de um minuto.
- [ ] `syscallcage doctor` confirma ambiente pronto logo após instalação.
- [ ] README reflete a realidade exata do que existe (nenhuma URL ou
      funcionalidade documentada que não esteja de fato disponível).

## O que este spec explicitamente NÃO faz

- Não implementa domínio próprio (`syscallcage.dev`) — usa GitHub raw
  como ponte honesta até lá.
- Não implementa backoff exponencial no restart do `watch` — reinício
  imediato é aceitável nesta versão; refinamento futuro.
- Não mexe na landing Hugo (isso é a etapa seguinte, spec GT-10 já
  existente, a ser retomado depois deste).
- Não dockeriza nada — decisão já registrada e mantida.
