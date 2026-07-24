// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

use std::ffi::CString;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use nix::sys::wait::{waitpid, WaitStatus};
use nix::unistd::{execvp, fork, ForkResult};
use thiserror::Error;

use crate::enforcer::{Action, Enforcer, Event, KillReason};
use crate::logging;
use crate::monitor::Monitor;
use crate::policy::Policy;

pub struct WatchConfig {
    pub policy: Policy,
    pub command: Vec<String>,
    pub max_restarts: Option<u32>,
}

#[derive(Debug, Error)]
pub enum WatchError {
    #[error("erro de sistema (fork/exec/wait): {0}")]
    Errno(#[from] nix::Error),
    #[error("erro de monitor: {0}")]
    Monitor(#[from] crate::monitor::MonitorError),
    #[error("número máximo de reinícios atingido, supervisão encerrada")]
    MaxRestartsExceeded,
    #[error("agente encerrado por violação de política, supervisão interrompida")]
    PolicyViolationHalt,
}

/// "Se meu pai morrer, me mande SIGTERM automaticamente" -- garante que
/// matar o SyscallCage nunca deixa o agente supervisionado rodando sem
/// vigilância (zero trust: ausência de supervisor implica parar o
/// supervisionado, nunca deixá-lo correr solto).
#[cfg(target_os = "linux")]
pub fn set_parent_death_signal() -> Result<(), std::io::Error> {
    let ret = unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGTERM) };
    if ret != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

pub fn parse_c_command(args: &[String]) -> Result<Vec<CString>, (usize, String)> {
    let mut c_args = Vec::with_capacity(args.len());
    for (idx, arg) in args.iter().enumerate() {
        match CString::new(arg.as_str()) {
            Ok(c_str) => c_args.push(c_str),
            Err(e) => return Err((idx, format!("argumento {}: {}", idx, e))),
        }
    }
    Ok(c_args)
}

pub fn run(config: WatchConfig) -> Result<(), WatchError> {
    let policy = config.policy;
    let mut restart_count = 0u32;

    loop {
        if let Some(max) = config.max_restarts {
            if restart_count >= max {
                logging::fatal("watch", "número máximo de reinícios atingido, encerrando supervisão");
                return Err(WatchError::MaxRestartsExceeded);
            }
        }

        match unsafe { fork()? } {
            ForkResult::Child => {
                if let Err(e) = set_parent_death_signal() {
                    logging::fatal("watch", &format!("falha ao configurar PR_SET_PDEATHSIG: {}", e));
                    std::process::exit(127);
                }
                let c_command = match parse_c_command(&config.command) {
                    Ok(cmd) => cmd,
                    Err((idx, err)) => {
                        logging::fatal(
                            "watch",
                            &format!("o comando contém um caractere nulo inválido na posição {}: {}", idx, err),
                        );
                        std::process::exit(2);
                    }
                };
                let Err(e) = execvp(&c_command[0], &c_command);
                logging::fatal(
                    "watch",
                    &format!("falha ao executar '{}': {}", config.command.get(0).cloned().unwrap_or_default(), e),
                );
                std::process::exit(127);
            }
            ForkResult::Parent { child } => {
                let pid = child.as_raw() as u32;
                logging::log(logging::Entry {
                    timestamp: logging::get_timestamp(),
                    level: "info",
                    component: "watch",
                    message: "agente iniciado sob supervisão",
                    pid: Some(pid),
                    event_type: None,
                    target: None,
                    action: None,
                });

                let enforcer = Arc::new(Enforcer::new(policy.clone()));
                let kill_reason: Arc<Mutex<Option<KillReason>>> = Arc::new(Mutex::new(None));
                let kr_clone = kill_reason.clone();
                let enf_clone = enforcer.clone();

                let handler = move |evt: Event| match enf_clone.enforce(&evt) {
                    Ok(Action::Kill) => {
                        *kr_clone.lock().unwrap() = Some(KillReason::PolicyViolation);
                    }
                    Ok(_) => {}
                    Err(e) => {
                        logging::log(logging::Entry {
                            timestamp: logging::get_timestamp(),
                            level: "warn",
                            component: "watch",
                            message: &format!("erro ao processar evento: {}", e),
                            pid: Some(evt.pid),
                            event_type: None,
                            target: None,
                            action: None,
                        });
                    }
                };

                // Anexa os hooks eBPF assim que o PID do filho nasce, antes
                // de qualquer waitpid -- anexar depois de esperar o filho
                // terminar seria tarde demais.
                let monitor = Arc::new(Monitor::new(pid, &policy, handler)?);
                
                let monitor_clone = monitor.clone();
                std::thread::spawn(move || {
                    if let Err(e) = monitor_clone.start() {
                        logging::fatal("watch", &format!("falha no monitor: {}", e));
                    }
                });

                let wait_res = waitpid(child, None);
                monitor.close(); // Ensure monitor loop stops now that child is dead

                match wait_res? {
                    WaitStatus::Signaled(_, sig, _) => {
                        if *kill_reason.lock().unwrap() == Some(KillReason::PolicyViolation) {
                            logging::fatal(
                                "watch",
                                "agente encerrado por violação de política -- supervisão interrompida, requer intervenção humana",
                            );
                            return Err(WatchError::PolicyViolationHalt);
                        }
                        logging::log(logging::Entry {
                            timestamp: logging::get_timestamp(),
                            level: "warn",
                            component: "watch",
                            message: &format!("agente encerrado pelo sinal {:?}, reiniciando", sig),
                            pid: Some(pid),
                            event_type: None,
                            target: None,
                            action: None,
                        });
                    }
                    WaitStatus::Exited(_, code) => {
                        logging::log(logging::Entry {
                            timestamp: logging::get_timestamp(),
                            level: "warn",
                            component: "watch",
                            message: &format!("agente encerrou com código {}, reiniciando", code),
                            pid: Some(pid),
                            event_type: None,
                            target: None,
                            action: None,
                        });
                    }
                    _ => {}
                }
                restart_count += 1;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(target_os = "linux")]
    fn test_set_parent_death_signal_succeeds() {
        // Não simula morte real do pai -- só confirma que a chamada de
        // prctl em si tem sucesso (retorno 0), o que já valida a integração
        // correta com libc.
        assert!(set_parent_death_signal().is_ok());
    }

    #[test]
    fn test_parse_c_command_valid() {
        let args = vec!["ls".to_string(), "-l".to_string()];
        let res = parse_c_command(&args);
        assert!(res.is_ok());
        let c_args = res.unwrap();
        assert_eq!(c_args.len(), 2);
    }

    #[test]
    fn test_parse_c_command_null_byte_returns_err() {
        let args = vec!["echo".to_string(), "hello\0world".to_string()];
        let res = parse_c_command(&args);
        assert!(res.is_err());
        let (idx, _err) = res.unwrap_err();
        assert_eq!(idx, 1);
    }
}
