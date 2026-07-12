// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

pub mod logging;
pub mod policy;
pub mod enforcer;
pub mod monitor;
pub mod policy_generator;
pub mod policy_sync_compiler;
pub mod watch;

use clap::Parser;
use std::sync::Arc;
use crate::policy::Policy;
use crate::enforcer::{Event, Enforcer};
use crate::monitor::{Monitor, MonitorError};

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(long, help = "PID do processo alvo a monitorar")]
    pid: Option<u32>,

    #[arg(long, help = "Caminho para o arquivo YAML de política")]
    policy: Option<String>,

    #[arg(long, help = "Caminho para o arquivo de log para espelhar eventos em formato JSONL")]
    log_file: Option<String>,

    #[command(subcommand)]
    command: Option<Subcommands>,
}

#[derive(clap::Subcommand, Debug)]
enum Subcommands {
    #[command(name = "generate-policy", about = "Gera uma política baseada no log de eventos")]
    GeneratePolicy {
        #[arg(long, help = "Caminho do arquivo de log JSONL de entrada")]
        from_log: std::path::PathBuf,

        #[arg(long, default_value = "generated-policy.yaml", help = "Caminho do arquivo YAML de saída")]
        output: std::path::PathBuf,
    },
    #[command(name = "doctor", about = "Realiza diagnósticos do ambiente operacional")]
    Doctor,
    #[command(name = "watch", about = "Cria e supervisiona o processo do agente desde o nascimento")]
    Watch {
        #[arg(long, help = "Caminho para o arquivo YAML de política")]
        policy: std::path::PathBuf,

        #[arg(long, help = "Número máximo de reinícios automáticos (padrão: ilimitado)")]
        max_restarts: Option<u32>,

        #[arg(last = true, required = true, help = "Comando do agente a ser executado e supervisionado")]
        command: Vec<String>,
    },
}

#[tokio::main]
async fn main() {
    let args = Args::parse();

    if let Some(sub) = args.command {
        match sub {
            Subcommands::GeneratePolicy { from_log, output } => {
                if let Err(e) = policy_generator::run_generator(&from_log, &output) {
                    logging::fatal("main", &format!("falha ao gerar política: {}", e));
                    std::process::exit(1);
                }
                std::process::exit(0);
            }
            Subcommands::Doctor => {
                run_doctor();
                std::process::exit(0);
            }
            Subcommands::Watch { policy, max_restarts, command } => {
                let config = watch::WatchConfig {
                    policy_path: policy,
                    command,
                    max_restarts,
                };
                if let Err(e) = watch::run(config) {
                    logging::fatal("main", &format!("supervisão watch encerrada: {}", e));
                    std::process::exit(1);
                }
                std::process::exit(0);
            }
        }
    }

    // Modo legado/padrão de monitoramento
    let pid = match args.pid {
        Some(p) if p != 0 => p,
        _ => {
            logging::fatal("main", "flag --pid é obrigatória e deve ser diferente de zero quando executando em modo monitor");
            std::process::exit(1);
        }
    };

    let policy_path = match args.policy {
        Some(ref p) if !p.is_empty() => p,
        _ => {
            logging::fatal("main", "flag --policy é obrigatória quando executando em modo monitor");
            std::process::exit(1);
        }
    };

    // Configura espelhamento de arquivo de log se solicitado
    if let Some(ref log_path_str) = args.log_file {
        if let Err(e) = logging::set_file_output(std::path::Path::new(log_path_str)) {
            logging::fatal("main", &format!("falha ao inicializar arquivo de log {:?}: {}", log_path_str, e));
            std::process::exit(1);
        }
    }

    let pol = match Policy::load(std::path::Path::new(policy_path)) {
        Ok(p) => p,
        Err(e) => {
            logging::fatal("main", &format!("falha ao carregar política: {}", e));
            std::process::exit(1);
        }
    };

    let enf = Arc::new(Enforcer::new(pol.clone()));

    let enf_clone = enf.clone();
    let handler = move |evt: Event| {
        if let Err(e) = enf_clone.enforce(&evt) {
            let err_msg = format!("erro ao processar evento: {}", e);
            let et_str = format!("{:?}", evt.event_type);
            logging::log(logging::Entry {
                timestamp: logging::get_timestamp(),
                level: "warn",
                component: "main",
                message: &err_msg,
                pid: Some(evt.pid),
                event_type: Some(et_str.as_str()),
                target: Some(evt.target.as_str()),
                action: None,
            });
        }
    };

    let monitor = match Monitor::new(pid, &pol, handler) {
        Ok(m) => Arc::new(m),
        Err(e) => {
            logging::fatal("main", &format!("falha ao inicializar monitor: {}", e));
            std::process::exit(1);
        }
    };

    logging::log(logging::Entry {
        timestamp: logging::get_timestamp(),
        level: "info",
        component: "main",
        message: "syscallcage iniciado",
        pid: Some(pid),
        event_type: None,
        target: None,
        action: None,
    });

    let monitor_clone = monitor.clone();
    let monitor_handle = tokio::task::spawn_blocking(move || {
        monitor_clone.start()
    });

    // infalível: falha apenas se o runtime tokio não estiver ativo, o que é impossível aqui
    let mut sigint = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())
        .expect("falha ao registrar SIGINT");
    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .expect("falha ao registrar SIGTERM");

    let mut monitor_handle = std::pin::pin!(monitor_handle);

    tokio::select! {
        _ = sigint.recv() => {
            logging::log(logging::Entry {
                timestamp: logging::get_timestamp(),
                level: "info",
                component: "main",
                message: "sinal de encerramento recebido, desligando",
                pid: Some(pid),
                event_type: None,
                target: None,
                action: None,
            });
            monitor.close();
            if let Err(e) = (&mut monitor_handle).await {
                logging::info("main", &format!("aviso: erro ao aguardar encerramento do monitor sob SIGINT: {}", e));
            }
        }
        _ = sigterm.recv() => {
            logging::log(logging::Entry {
                timestamp: logging::get_timestamp(),
                level: "info",
                component: "main",
                message: "sinal de encerramento recebido, desligando",
                pid: Some(pid),
                event_type: None,
                target: None,
                action: None,
            });
            monitor.close();
            if let Err(e) = (&mut monitor_handle).await {
                logging::info("main", &format!("aviso: erro ao aguardar encerramento do monitor sob SIGTERM: {}", e));
            }
        }
        res = &mut monitor_handle => {
            monitor.close();
            let monitor_err = match res {
                Ok(inner_res) => inner_res.err(),
                Err(join_err) => Some(MonitorError::IO(std::io::Error::other(join_err.to_string()))),
            };

            if monitor.exited_because_target_died() {
                logging::log(logging::Entry {
                    timestamp: logging::get_timestamp(),
                    level: "info",
                    component: "main",
                    message: "processo monitorado encerrou, syscallcage finalizado normalmente",
                    pid: Some(pid),
                    event_type: None,
                    target: None,
                    action: None,
                });
                return;
            }

            let mut msg = "monitor encerrou inesperadamente, syscallcage não está mais protegendo o PID".to_string();
            if let Some(err) = monitor_err {
                msg = format!("{}: {}", msg, err);
            }
            logging::fatal("main", &msg);
            std::process::exit(1);
        }
    }

    logging::log(logging::Entry {
        timestamp: logging::get_timestamp(),
        level: "info",
        component: "main",
        message: "syscallcage encerrado",
        pid: Some(pid),
        event_type: None,
        target: None,
        action: None,
    });
}

fn run_doctor() {
    println!("SyscallCage — diagnóstico do ambiente\n");

    // 1. Versão do binário
    println!("✓ Binário instalado: v{}", env!("CARGO_PKG_VERSION"));

    // 2. Kernel
    let kernel = std::fs::read_to_string("/proc/sys/kernel/osrelease")
        .unwrap_or_else(|_| "desconhecido".into());
    println!("✓ Kernel detectado: {}", kernel.trim());

    // 3. Suporte a BPF LSM
    if crate::monitor::bpf_lsm_available() {
        println!("✓ BPF LSM disponível — modo síncrono (recomendado) será usado.");
    } else {
        println!("! BPF LSM indisponível — modo reativo (fallback) será usado.");
        println!("  Isso ainda funciona, mas o bloqueio acontece após a violação, não antes.");
    }

    // 4. eBPF companion binário encontrado
    match crate::monitor::locate_ebpf_binary() {
        Ok(path) => println!("✓ Programa eBPF encontrado em: {}", path.display()),
        Err(_) => println!("✗ Programa eBPF não encontrado. Reinstale ou defina SYSCALLCAGE_EBPF_PATH."),
    }

    // 5. Privilégio
    if unsafe { libc::geteuid() } == 0 {
        println!("✓ Rodando como root — pronto para anexar eBPF.");
    } else {
        println!("! Não está rodando como root. Use 'sudo' ao executar o SyscallCage de verdade.");
    }

    println!("\nSe todos os itens acima estão ✓, você está pronto para usar.");
}
