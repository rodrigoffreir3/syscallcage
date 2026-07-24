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

    #[arg(long, help = "Modo dry-run: apenas audita as violações, sem bloqueá-las")]
    dry_run: bool,

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
        policy: Option<std::path::PathBuf>,

        #[arg(long, help = "Número máximo de reinícios automáticos (padrão: ilimitado)")]
        max_restarts: Option<u32>,

        #[arg(last = true, required = true, help = "Comando do agente a ser executado e supervisionado")]
        command: Vec<String>,
    },
}

fn resolve_policy(policy_arg: Option<String>) -> std::path::PathBuf {
    if let Some(p) = policy_arg {
        if !p.is_empty() {
            return std::path::PathBuf::from(p);
        }
    }
    match policy::discovery::discover_policy(&std::env::current_dir().unwrap_or_default()) {
        Ok(Some(p)) => {
            logging::info("main", &format!("usando política descoberta automaticamente em {}", p.display()));
            p
        }
        Ok(None) => {
            logging::fatal("main", "nenhuma política encontrada e --policy não foi fornecido");
            std::process::exit(1);
        }
        Err(e) => {
            logging::fatal("main", &format!("erro ao descobrir política: {}", e));
            std::process::exit(1);
        }
    }
}

#[tokio::main]
async fn main() {
    let mut args = Args::parse();

    if let Some(sub) = args.command.take() {
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
                let policy_path = resolve_policy(policy.map(|p| p.display().to_string()));
                let mut pol = match Policy::load(&policy_path) {
                    Ok(p) => p,
                    Err(e) => {
                        logging::fatal("main", &format!("falha ao carregar política: {}", e));
                        std::process::exit(1);
                    }
                };
                if args.dry_run {
                    pol.force_dry_run();
                    logging::info("main", "modo dry-run ativado: violações serão apenas auditadas");
                }
                let config = watch::WatchConfig {
                    policy: pol,
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

    let policy_path = resolve_policy(args.policy);

    // Configura espelhamento de arquivo de log se solicitado
    if let Some(ref log_path_str) = args.log_file {
        if let Err(e) = logging::set_file_output(std::path::Path::new(log_path_str)) {
            logging::fatal("main", &format!("falha ao inicializar arquivo de log {:?}: {}", log_path_str, e));
            std::process::exit(1);
        }
    }

    let mut pol = match Policy::load(&policy_path) {
        Ok(p) => p,
        Err(e) => {
            logging::fatal("main", &format!("falha ao carregar política: {}", e));
            std::process::exit(1);
        }
    };
    if args.dry_run {
        pol.force_dry_run();
        logging::info("main", "modo dry-run ativado: violações serão apenas auditadas");
    }

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
    let mut sigint = match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt()) {
        Ok(s) => s,
        Err(e) => {
            logging::fatal("main", &format!("falha ao registrar SIGINT: {}", e));
            std::process::exit(1);
        }
    };
    let mut sigterm = match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
        Ok(s) => s,
        Err(e) => {
            logging::fatal("main", &format!("falha ao registrar SIGTERM: {}", e));
            std::process::exit(1);
        }
    };

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

#[derive(Debug, PartialEq, Eq)]
pub enum CheckStatus {
    Ok,
    Warn,
    Error,
}

#[derive(Debug)]
pub struct DoctorCheck {
    pub name: String,
    pub status: CheckStatus,
    pub message: String,
    pub detail: Option<String>,
}

#[derive(Debug)]
pub struct DoctorReport {
    pub checks: Vec<DoctorCheck>,
    pub is_root: bool,
    pub has_fatal_error: bool,
}

pub fn collect_doctor_report() -> DoctorReport {
    let is_root = unsafe { libc::geteuid() } == 0;
    let mut checks = Vec::new();
    let mut has_fatal_error = false;

    // 1. Versão do binário
    checks.push(DoctorCheck {
        name: "Binário instalado".to_string(),
        status: CheckStatus::Ok,
        message: format!("v{}", env!("CARGO_PKG_VERSION")),
        detail: None,
    });

    // 2. Kernel
    let kernel = std::fs::read_to_string("/proc/sys/kernel/osrelease")
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|_| "desconhecido".into());
    checks.push(DoctorCheck {
        name: "Kernel detectado".to_string(),
        status: CheckStatus::Ok,
        message: kernel,
        detail: None,
    });

    // 3. Suporte a BPF LSM
    if crate::monitor::bpf_lsm_available() {
        checks.push(DoctorCheck {
            name: "BPF LSM".to_string(),
            status: CheckStatus::Ok,
            message: "disponível — modo síncrono (recomendado) será usado.".to_string(),
            detail: None,
        });
    } else {
        checks.push(DoctorCheck {
            name: "BPF LSM".to_string(),
            status: CheckStatus::Warn,
            message: "indisponível — modo reativo (fallback) será usado.".to_string(),
            detail: Some("Isso ainda funciona, mas o bloqueio acontece após a violação, não antes.".to_string()),
        });
    }

    // 4. eBPF embutido e verifier
    match crate::monitor::doctor_check_ebpf() {
        Ok((size, hash, verifier_res)) => {
            checks.push(DoctorCheck {
                name: "Objeto eBPF embutido".to_string(),
                status: CheckStatus::Ok,
                message: format!("{} bytes, sha256 {}", size, hash),
                detail: None,
            });

            match verifier_res {
                Ok(_) => {
                    checks.push(DoctorCheck {
                        name: "Verifier do kernel".to_string(),
                        status: CheckStatus::Ok,
                        message: "aceitou o carregamento de teste dos programas LSM".to_string(),
                        detail: None,
                    });
                }
                Err(e) => {
                    if !is_root {
                        checks.push(DoctorCheck {
                            name: "Verifier do kernel".to_string(),
                            status: CheckStatus::Warn,
                            message: "não foi possível testar o verifier sem privilégios de root (EPERM).".to_string(),
                            detail: None,
                        });
                    } else {
                        checks.push(DoctorCheck {
                            name: "Verifier do kernel".to_string(),
                            status: CheckStatus::Error,
                            message: format!("rejeitou os programas LSM: {:?}", e),
                            detail: None,
                        });
                        has_fatal_error = true;
                    }
                }
            }
        }
        Err(e) => {
            checks.push(DoctorCheck {
                name: "Objeto eBPF embutido".to_string(),
                status: CheckStatus::Error,
                message: format!("erro ao verificar objeto eBPF: {}", e),
                detail: None,
            });
            has_fatal_error = true;
        }
    }

    // 5. Privilégio
    if is_root {
        checks.push(DoctorCheck {
            name: "Privilégios".to_string(),
            status: CheckStatus::Ok,
            message: "Rodando como root — pronto para anexar eBPF.".to_string(),
            detail: None,
        });
    } else {
        checks.push(DoctorCheck {
            name: "Privilégios".to_string(),
            status: CheckStatus::Warn,
            message: "Não está rodando como root. Use 'sudo' ao executar o SyscallCage de verdade.".to_string(),
            detail: None,
        });
    }

    DoctorReport {
        checks,
        is_root,
        has_fatal_error,
    }
}

fn run_doctor() {
    println!("SyscallCage — diagnóstico do ambiente\n");
    let report = collect_doctor_report();

    for check in &report.checks {
        let prefix = match check.status {
            CheckStatus::Ok => "✓",
            CheckStatus::Warn => "!",
            CheckStatus::Error => "✗",
        };
        println!("{} {}: {}", prefix, check.name, check.message);
        if let Some(detail) = &check.detail {
            println!("  {}", detail);
        }
    }

    if report.has_fatal_error {
        std::process::exit(1);
    }

    println!("\nSe todos os itens acima estão ✓, você está pronto para usar.");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_collect_doctor_report_does_not_panic() {
        let report = collect_doctor_report();
        assert!(!report.checks.is_empty());

        if !report.is_root {
            assert!(!report.has_fatal_error, "doctor não deve gerar erro fatal sem privilégio");
            let priv_check = report.checks.iter().find(|c| c.name == "Privilégios");
            assert!(priv_check.is_some());
            assert_eq!(priv_check.unwrap().status, CheckStatus::Warn);
        }
    }
}
