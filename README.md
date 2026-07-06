# SyscallCage

**Deixe sua IA trabalhar sozinha no seu computador, sem medo do que ela pode fazer.**

## O problema

Você usa um agente de IA (Claude Code, Cursor, ou parecido) que edita arquivos e roda comandos sozinho, sem você aprovar cada passo. É rápido e útil — mas sempre fica aquele desconforto: *e se ele ler minha senha sem eu perceber? E se mandar alguma coisa pra internet sem eu autorizar? E se rodar um comando perigoso achando que estava ajudando?*

## O que o SyscallCage faz

Ele fica de olho no que o agente **realmente faz** no seu computador — não no que ele diz que vai fazer. Você define regras simples (que pastas ele pode ler, que sites ele pode acessar, o que ele nunca pode rodar), e o SyscallCage garante isso na hora, sem depender do agente cooperar ou avisar antes.

Se o agente tentar abrir um arquivo de senha, ou conectar num site que você não autorizou, a ação é barrada ali mesmo — na maioria dos casos, antes mesmo dela acontecer.

## Onde ele atua

Direto no sistema operacional, na camada mais baixa que existe: o kernel do Linux. Isso significa que ele enxerga tudo o que qualquer programa faz de verdade — abrir arquivo, rodar comando, conectar na internet — sem depender do agente ter uma função especial de "avisar antes" (o que a maioria nem tem, e o que existe pode ser ignorado ou falhar).

## Quando ele age

Toda vez, sem exceção. Não é uma checagem periódica nem uma revisão depois do fato — é vigilância contínua, enquanto o processo que você está protegendo estiver rodando.

## Por que ele é diferente

A abordagem mais comum hoje pra esse problema é colocar o agente inteiro dentro de uma caixa isolada — um ambiente virtual separado, tipo um computador dentro do computador. Funciona, mas tem um custo: é pesado, é lento pra configurar, e você perde a conveniência de trabalhar direto na sua pasta de projeto real, com seus arquivos de verdade.

O SyscallCage não isola nada. Ele deixa o agente trabalhar exatamente onde ele já estava trabalhando — e observa, no nível mais fundo do sistema, se algo passa da linha. É a diferença entre trancar alguém numa sala vazia versus ter um segurança de confiança olhando o que a pessoa faz na sala de sempre. O resultado prático: você não perde velocidade nem muda seu fluxo de trabalho pra ganhar segurança.

## Como instalar

```bash
curl -fsSL https://syscallcage.dev/install.sh | sh
```

Isso baixa o programa pronto pra usar, sem precisar instalar nada além disso. Depois, confirme que está tudo certo:

```bash
syscallcage doctor
```

## Como usar

Primeiro, escreva um arquivo pequeno dizendo o que é permitido:

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
sudo syscallcage --pid <PID-do-agente> --policy sua-politica.yaml
```

Pronto. Ele fica vigiando até o processo terminar ou você mandar parar.

### Não sabe o que colocar nas regras?

Deixe o SyscallCage descobrir sozinho, observando uma sessão real de uso:

```bash
sudo syscallcage --pid <PID> --policy configs/observar.yaml --log-file sessao.jsonl
# deixe o agente trabalhar normalmente...
syscallcage generate-policy --from-log sessao.jsonl --output minha-politica.yaml
```

Ele nunca sugere liberar arquivo de senha ou comando perigoso, mesmo que apareça na sessão observada — isso fica de fora por padrão, sempre.

## Importante saber antes de instalar

- **Só funciona em Linux.** A tecnologia usada (eBPF) é do kernel Linux — não existe em Windows nem Mac hoje. Rodar dentro do WSL2 (Linux dentro do Windows) também não funciona de forma confiável — testamos.
- **Pede permissão de administrador (`sudo`) pra rodar**, porque precisa de acesso profundo ao sistema pra fazer esse tipo de vigilância. Isso é esperado e necessário pra esse tipo de ferramenta.
- Documentamos abertamente os limites atuais do projeto — nenhuma promessa exagerada. Veja a seção de limitações no repositório.

## Licença

Código aberto, licença MPL 2.0. Use, modifique, e use até comercialmente — só pedimos que mudanças feitas nos arquivos deste projeto continuem abertas também.

## Por que existe

Nasceu da mesma pesquisa por trás do Imunno System, um antivírus de comportamento para servidores Linux com patente registrada no Brasil. O SyscallCage aplica a mesma ideia — observar comportamento real, não confiar em promessa — a um problema novo: deixar IA trabalhar sozinha sem abrir mão de segurança.
