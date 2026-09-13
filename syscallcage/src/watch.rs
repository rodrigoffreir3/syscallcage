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
    if args.is_empty() {
        return Err((0, "comando não pode ser vazio".to_string()));
    }
    let mut c_args = Vec::with_capacity(args.len());
    for (idx, arg) in args.iter().enumerate() {
        match CString::new(arg.as_str()) {
            Ok(c_str) => c_args.push(c_str),
            Err(e) => return Err((idx, format!("argumento {}: {}", idx, e))),
        }
    }
    Ok(c_args)
}

/// Verifica se o pai atual é o mesmo de antes do fork, para evitar orfandade.
pub fn check_parent_alive(original_ppid: libc::pid_t) -> bool {
    let current_ppid = unsafe { libc::getppid() };
    current_ppid == original_ppid
}

/// Aguarda a liberação bloqueando num pipe. Retorna erro se o pipe fechar sem o byte.
pub fn await_parent_release(read_fd: std::os::fd::RawFd) -> Result<(), std::io::Error> {
    let mut buf = [0u8; 1];
    let n = nix::unistd::read(read_fd, &mut buf)?;
    if n == 0 {
        return Err(std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "pipe fechado pelo pai sem liberação"));
    }
    Ok(())
}

pub fn run(config: WatchConfig) -> Result<(), WatchError> {
    let policy = config.policy;
    let mut restart_count = 0u32;

    loop {
        let parent_pid_antes = unsafe { libc::getpid() };
        let mut fds = [-1, -1];
        if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
            let e = nix::Error::last();
            logging::fatal("watch", &format!("falha ao criar pipe de sincronização: {}", e));
            return Err(WatchError::Errno(e));
        }
        let read_fd = fds[0];
        let write_fd = fds[1];

        match unsafe { fork()? } {
            ForkResult::Child => {
                if let Err(e) = nix::unistd::close(write_fd) {
                    logging::fatal("watch", &format!("falha ao fechar write_fd no filho: {}", e));
                    std::process::exit(127);
                }
                
                if let Err(e) = set_parent_death_signal() {
                    logging::fatal("watch", &format!("falha ao configurar PR_SET_PDEATHSIG: {}", e));
                    std::process::exit(127);
                }
                
                if !check_parent_alive(parent_pid_antes) {
                    logging::fatal("watch", "pai morreu durante o fork, abortando inicialização (evita orfandade)");
                    std::process::exit(127);
                }
                
                if let Err(e) = await_parent_release(read_fd) {
                    logging::fatal("watch", &format!("pai abortou a inicialização do monitor: {}", e));
                    std::process::exit(127);
                }
                
                if let Err(e) = nix::unistd::close(read_fd) {
                    logging::fatal("watch", &format!("falha ao fechar read_fd no filho: {}", e));
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
                if let Err(e) = nix::unistd::close(read_fd) {
                    logging::fatal("watch", &format!("falha ao fechar read_fd no pai: {}", e));
                }

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

                let monitor = match Monitor::new(pid, &policy, handler) {
                    Ok(m) => Arc::new(m),
                    Err(e) => {
                        if let Err(err_close) = nix::unistd::close(write_fd) {
                            logging::log(logging::Entry {
                                timestamp: logging::get_timestamp(),
                                level: "warn",
                                component: "watch",
                                message: &format!("falha ao fechar write_fd após erro no monitor: {}", err_close),
                                pid: Some(pid),
                                event_type: None,
                                target: None,
                                action: None,
                            });
                        }
                        return Err(WatchError::Monitor(e));
                    }
                };

                if let Err(e) = nix::unistd::write(write_fd, &[1]) {
                    logging::fatal("watch", &format!("falha ao sinalizar liberação para o filho: {}", e));
                    // Tentativa de fechar, mas sem abafar erro ou travar (se write falhou, pipe pode estar quebrado)
                    let _ = nix::unistd::close(write_fd);
                    return Err(WatchError::Errno(e));
                }
                
                if let Err(e) = nix::unistd::close(write_fd) {
                    logging::fatal("watch", &format!("falha ao fechar write_fd no pai após liberação: {}", e));
                }

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
                        let max = config.max_restarts.unwrap_or(0);
                        if restart_count >= max {
                            logging::log(logging::Entry {
                                timestamp: logging::get_timestamp(),
                                level: "warn",
                                component: "watch",
                                message: &format!("agente encerrado pelo sinal {:?}, supervisão finalizada", sig),
                                pid: Some(pid),
                                event_type: None,
                                target: None,
                                action: None,
                            });
                            return Ok(());
                        }
                        logging::log(logging::Entry {
                            timestamp: logging::get_timestamp(),
                            level: "warn",
                            component: "watch",
                            message: &format!("agente encerrado pelo sinal {:?}, reiniciando ({}/{})", sig, restart_count + 1, max),
                            pid: Some(pid),
                            event_type: None,
                            target: None,
                            action: None,
                        });
                        std::thread::sleep(std::time::Duration::from_millis(1000));
                    }
                    WaitStatus::Exited(_, code) => {
                        if code == 0 {
                            logging::log(logging::Entry {
                                timestamp: logging::get_timestamp(),
                                level: "info",
                                component: "watch",
                                message: "agente finalizou com sucesso (código 0), encerrando supervisão",
                                pid: Some(pid),
                                event_type: None,
                                target: None,
                                action: None,
                            });
                            return Ok(());
                        }
                        let max = config.max_restarts.unwrap_or(0);
                        if restart_count >= max {
                            logging::log(logging::Entry {
                                timestamp: logging::get_timestamp(),
                                level: "warn",
                                component: "watch",
                                message: &format!("agente encerrou com erro (código {}), supervisão finalizada", code),
                                pid: Some(pid),
                                event_type: None,
                                target: None,
                                action: None,
                            });
                            return Ok(());
                        }
                        logging::log(logging::Entry {
                            timestamp: logging::get_timestamp(),
                            level: "warn",
                            component: "watch",
                            message: &format!("agente encerrou com código {}, reiniciando ({}/{})", code, restart_count + 1, max),
                            pid: Some(pid),
                            event_type: None,
                            target: None,
                            action: None,
                        });
                        std::thread::sleep(std::time::Duration::from_millis(1000));
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

    #[test]
    fn test_parse_c_command_empty_returns_err() {
        let args: Vec<String> = vec![];
        let res = parse_c_command(&args);
        assert!(res.is_err());
        let (idx, _err) = res.unwrap_err();
        assert_eq!(idx, 0);
    }

    #[test]
    fn test_check_parent_alive() {
        let me = unsafe { libc::getpid() };
        // Passando meu próprio PID fingindo ser o "pai original"
        assert!(!check_parent_alive(me));
        
        // Passando meu ppid real
        let real_ppid = unsafe { libc::getppid() };
        assert!(check_parent_alive(real_ppid));
    }

    #[test]
    fn test_await_parent_release_success() {
        let mut fds = [-1, -1];
        unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) };
        let read_fd = fds[0];
        let write_fd = fds[1];
        nix::unistd::write(write_fd, &[1]).unwrap();
        assert!(await_parent_release(read_fd).is_ok());
        nix::unistd::close(write_fd).unwrap();
        nix::unistd::close(read_fd).unwrap();
    }

    #[test]
    fn test_await_parent_release_eof() {
        let mut fds = [-1, -1];
        unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) };
        let read_fd = fds[0];
        let write_fd = fds[1];
        nix::unistd::close(write_fd).unwrap(); // Simula morte do pai ou falha do eBPF
        let res = await_parent_release(read_fd);
        assert!(res.is_err());
        assert_eq!(res.unwrap_err().kind(), std::io::ErrorKind::UnexpectedEof);
        nix::unistd::close(read_fd).unwrap();
    }
}
