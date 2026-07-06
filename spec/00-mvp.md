SPEC — Agent Cage (nome provisório)
O problema, sem enrolação
Dev roda agente de IA autônomo (Claude Code, Cursor, Codex CLI) em modo auto-approve no próprio filesystem, sem sandbox pesado, porque sandbox pesado quebra o fluxo de trabalho real. O agente pode, sem querer ou por prompt injection, ler .env, vazar credencial numa chamada de rede, ou rodar algo destrutivo. Hoje a defesa é "confiar e rezar" ou "sandbox completo e perder produtividade". Não existe meio termo local, leve, em tempo real.
O que o MVP faz (e só isso)
Um daemon eBPF que:
Observa syscalls de um processo (e seus filhos) via tracepoint/kprobe.
Compara contra uma política declarativa (YAML) de paths permitidos, domínios de rede permitidos, e syscalls proibidas.
Quando a política é violada: mata o processo (modo enforce) ou só loga e alerta (modo monitor) — configurável.
O que o MVP NÃO faz (fora de escopo, de propósito)
Não substitui sandbox completo (namespace/cgroup) — é uma camada a mais, não a única defesa.
Não tem UI. CLI + log estruturado (JSON) só.
Não suporta múltiplas políticas simultâneas nesta fase — um processo, uma política, ponto.
Não intercepta conteúdo de rede (não é proxy TLS) — só decide se a conexão pode abrir ou não, baseado em domínio/IP resolvido.
Limitações Conhecidas (Design de MVP BPF)
* DNS Parsing (Pointer Assumption): O snooping DNS assume que a resposta utiliza compressão (pointer 0xC0). Nomes totalmente literais na Answer Section não são suportados e resultarão em bypass seguro (cai pro bloqueio de IP cru).
* Limpeza de Mapas por LRU: Os BPF Maps de correlação DNS (pending_dns_query, dns_recv_buff) usam LRU_HASH. Se um processo morre com query pendente, a entrada não é removida instantaneamente; ela expira eventualmente sob pressão de memória. Não causa OOM (Out Of Memory), mas não é uma limpeza rigorosa no momento do exit.
* Limite de Subdomínios (10 Labels): Devido às restrições do BPF Verifier de saltos em loops não determinísticos, o loop que lê o QNAME (nome pesquisado) salta no máximo 10 segmentos (labels separados por ponto). Domínios com mais de 10 níveis de profundidade vão quebrar o parsing, enviando o offset pra posição errada, resultando no descarte daquela resposta DNS.
* Ação Reativa (Kill Assíncrono): A ação de encerramento (kill) é disparada em Userspace após consumir o evento do Ring Buffer eBPF, sendo reativa/assíncrona e não preventiva/síncrona (como seria por LSM BPF ou seccomp). Isso significa que o processo cobaia pode conseguir concluir ou obter retorno do syscall antes do recebimento do sinal SIGKILL.
Arquitetura mínima
syscallcage run --policy claude-code.yaml --pid <PID_do_agente>
     │
     ├── internal/policy    → parse do YAML, validação
     ├── internal/monitor   → attach eBPF (tracepoint syscalls: openat, connect, execve)
     ├── internal/enforcer  → decide: permitir / logar / matar
     └── cmd/syscallcage     → CLI (cobra ou flag simples, sem framework pesado)
Política declarativa — exemplo mínimo
# configs/claude-code.yaml
mode: enforce   # ou "monitor" para só logar sem matar
filesystem:
  allow_read:
    - "/home/rodrigo/projetos/**"
  allow_write:
    - "/home/rodrigo/projetos/**"
  deny_always:          # checado ANTES do allow, sempre vence
    - "**/.env"
    - "**/.ssh/**"
    - "**/id_rsa*"
network:
  allow_domains:
    - "api.anthropic.com"
    - "github.com"
  deny_all_else: true
syscalls:
  deny:
    - "execve:/bin/sh"      # bloqueia spawn de shell reverso clássico
    - "ptrace"              # bloqueia debugger/injeção em outro processo
Critério de sucesso do MVP (binário, testável)
Processo tenta ler .env fora do allow-list → morre em <50ms, log gravado.
Processo tenta curl para domínio fora da allow-list → conexão recusada.
Processo tenta execve("/bin/sh") → bloqueado.
Processo operando dentro da política → zero overhead perceptível (medir: tempo de execução de uma tarefa real do agente com e sem o cage rodando, diferença tem que ser <5%).
Modo monitor nunca mata processo, só loga — para calibrar política sem risco antes de ativar enforce.
Princípios aplicados
Simplicidade: uma política YAML, um binário, sem dependência de daemon externo (nada de precisar rodar Docker pra rodar o guardrail).
Zero trust: deny_always sempre vence allow, sem exceção, sem "modo debug que desliga tudo" escondido no código.
Testável: cada regra da política tem teste de unidade simulando o syscall via mock antes de qualquer teste real com eBPF de verdade (eBPF real precisa de kernel + privilégio, testes de lógica de política não).
Não quebra nada: roda como processo separado, observando por PID — não precisa modificar o agente (Claude Code etc) para funcionar.
Ordem de implementação (spec-driven, menor risco primeiro)
internal/policy: parser + validador do YAML, com testes — zero eBPF envolvido nesta etapa, é só parsing e regras de match de path/glob.
internal/enforcer: dado um "evento" simulado (struct Go, não syscall real ainda), decide permitir/logar/matar — testável sem kernel.
internal/monitor: aqui entra eBPF de verdade (tracepoint em sys_enter_openat, sys_enter_connect, sys_enter_execve), primeiro só logando (modo monitor), sem matar nada.
Conectar monitor → enforcer → ação real de matar processo (SIGKILL via PID), só depois que 1-3 estiverem testados e estáveis.
CLI (cmd/syscallcage) por último — é a parte menos arriscada.
Stack
Go + cilium/ebpf (biblioteca, não precisa de bcc/python, compila estático, mesma stack do Imunno). YAML via gopkg.in/yaml.v3. Zero framework CLI pesado — flag da stdlib ou spf13/cobra se quiser subcomando bonito.