# Relatório de Progresso: SyscallCage

> [!NOTE]
> Este documento sumariza todas as investigações, correções e configurações realizadas na máquina virtual Alpine para o desenvolvimento do SyscallCage, bem como os próximos passos pendentes para a conclusão da versão `v0.2.0`.

## O que foi concluído com sucesso ✅

1. **Configuração da Máquina Virtual de Teste:**
   - Montagem de um disco persistente formatado em `ext4` no diretório `/mnt/disk` da VM Alpine (substituindo o VirtualBox shared folders que não dispunha de drivers adequados).
   - Instalação e configuração de todo o ecossistema necessário no Alpine: `rustup` (versão *nightly*), `clang`, `llvm`, bibliotecas BPF, `kernel-headers`, `gcc` e utilitários de sistema.
   
2. **Correção do Target eBPF (`invalid section`):**
   - Identificamos por que o programa eBPF não estava sendo aceito pelo kernel.
   - Ajustamos a configuração de compilação para garantir que o binário eBPF seja sempre gerado para o target genérico correto: `bpfel-unknown-none`, e não associado ao Linux padrão.

3. **Correção de Linker e Variáveis de Ambiente:**
   - A compilação em modo silencioso via SSH falhava porque o Rust perdia o binário `cc`. O PATH agora exporta corretamente `/usr/bin:/bin:/sbin` para garantir a ligação (linking) bem-sucedida do executável na VM.

4. **Identificação e Solução do *Deadlock* (Zumbis):**
   - O sintoma relatado de travamentos ocorria porque o processo monitor ficava "preso" e os agentes supervisionados (quando falhavam ou concluíam) viravam "zumbis" sem serem limpos pelo sistema (`Z status`).
   - O erro foi causado pela chamada síncrona dentro da thread principal impedindo o `waitpid` de ser invocado. 
   - **Solução implementada**: Refatoramos o arquivo `watch.rs` para lançar o `Monitor::start()` (loop de eventos do BPF) em uma **thread separada em background**, liberando a thread principal do `syscallcage` para ouvir e limpar os processos filhos que morrem com `waitpid`.

---

## O que falta fazer / Próximos Passos ⏳

> [!WARNING]
> Tivemos um leve atraso no final devido a um desalinhamento entre o código da sua máquina (`watch.rs` host) e o repositório avulso na VM. Os comandos pendentes a seguir são simples, mas a confirmação final precisará ser feita na próxima sessão.

1. **Validação Final dos Testes (Scenarios 1, 2 e 3)**
   - Rodar o script `/mnt/disk/test.sh` na VM compilada com o `watch.rs` refatorado e atestar que os zumbis deixaram de existir.

2. **Teste Ponta a Ponta (E2E) e Doctor**
   - Testar o comportamento do script `install.sh` do zero e confirmar que a ferramenta de diagnóstico `syscallcage doctor` está reportando todos os hooks com exatidão.

3. **Lançamento (Release v0.2.0)**
   - Fazer o build final do bundle em modo release.
   - Criar e subir a tag `v0.2.0` no repositório.

4. **Documentação Segura**
   - Documentar os passos técnicos de compilação sem expor IPs, paths host ou credenciais no repositório do projeto.
