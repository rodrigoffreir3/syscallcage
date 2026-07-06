// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

use crate::logging;
use crate::policy::{Mode, Policy};
use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventType {
    Read,
    Write,
    Network,
    Syscall,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    Allow,
    Log,
    Kill,
}

pub struct Event {
    pub pid: u32,
    pub event_type: EventType,
    pub target: String,
    pub resolved: bool,
}

#[derive(Debug, Error)]
pub enum EnforceError {
    #[error("falha ao matar processo {pid}: {source}")]
    KillFailed { pid: u32, source: std::io::Error },
}

pub trait ProcessKiller {
    fn kill(&self, pid: u32) -> std::io::Result<()>;
}

pub struct RealKiller;
impl ProcessKiller for RealKiller {
    fn kill(&self, pid: u32) -> std::io::Result<()> {
        let res = unsafe { libc::kill(pid as libc::pid_t, libc::SIGKILL) };
        if res == -1 {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(())
        }
    }
}

pub struct Enforcer<K: ProcessKiller = RealKiller> {
    policy: Policy,
    killer: K,
}

impl Enforcer<RealKiller> {
    pub fn new(policy: Policy) -> Self {
        Self {
            policy,
            killer: RealKiller,
        }
    }
}

impl<K: ProcessKiller> Enforcer<K> {
    #[cfg(test)]
    pub fn with_killer(policy: Policy, killer: K) -> Self {
        Self { policy, killer }
    }

    pub fn enforce(&self, event: &Event) -> Result<Action, EnforceError> {
        let et_str = match event.event_type {
            EventType::Read => "read",
            EventType::Write => "write",
            EventType::Network => "network",
            EventType::Syscall => "syscall",
        };

        // Always log entry
        logging::log(logging::Entry {
            timestamp: logging::get_timestamp(),
            level: "info",
            component: "enforcer_debug",
            message: "event received",
            pid: Some(event.pid),
            event_type: Some(et_str),
            target: Some(&event.target),
            action: None,
        });

        let allowed = match event.event_type {
            EventType::Read => self.policy.path_allowed(&event.target, false),
            EventType::Write => self.policy.path_allowed(&event.target, true),
            EventType::Network => {
                // IPv6 é bloqueado explicitamente; IP sem DNS resolvido também (zero trust)
                if event.target == "<ipv6-nao-suportado>" || !event.resolved {
                    false
                } else {
                    self.policy.domain_allowed(&event.target)
                }
            }
            EventType::Syscall => !self.policy.syscall_denied(&event.target),
        };

        if allowed {
            logging::log(logging::Entry {
                timestamp: logging::get_timestamp(),
                level: "info",
                component: "enforcer",
                message: "event allowed by policy",
                pid: Some(event.pid),
                event_type: Some(et_str),
                target: Some(&event.target),
                action: Some("allow"),
            });
            return Ok(Action::Allow);
        }

        let mut should_kill = true;
        if event.event_type == EventType::Syscall {
            should_kill = self.policy.should_kill_on_syscall_deny(&event.target);
        }

        if self.policy.mode() == Mode::Enforce && should_kill {
            match self.killer.kill(event.pid) {
                Ok(()) => {
                    logging::log(logging::Entry {
                        timestamp: logging::get_timestamp(),
                        level: "warn",
                        component: "enforcer",
                        message: "violation detected, process killed",
                        pid: Some(event.pid),
                        event_type: Some(et_str),
                        target: Some(&event.target),
                        action: Some("kill"),
                    });
                    Ok(Action::Kill)
                }
                Err(source) => {
                    logging::log(logging::Entry {
                        timestamp: logging::get_timestamp(),
                        level: "fatal",
                        component: "enforcer",
                        message: "violation detected but failed to kill process",
                        pid: Some(event.pid),
                        event_type: Some(et_str),
                        target: Some(&event.target),
                        action: Some("kill_failed"),
                    });
                    Err(EnforceError::KillFailed {
                        pid: event.pid,
                        source,
                    })
                }
            }
        } else {
            logging::log(logging::Entry {
                timestamp: logging::get_timestamp(),
                level: "warn",
                component: "enforcer",
                message: if self.policy.mode() == Mode::Enforce {
                    "violation detected, allowed without kill (kill_on_deny is false)"
                } else {
                    "violation detected, allowed (monitor mode)"
                },
                pid: Some(event.pid),
                event_type: Some(et_str),
                target: Some(&event.target),
                action: Some("log"),
            });
            Ok(Action::Log)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
    use std::sync::Arc;

    #[derive(Clone)]
    struct MockKiller {
        killed: Arc<AtomicBool>,
        kill_pid: Arc<AtomicU32>,
        should_fail: bool,
    }

    impl ProcessKiller for MockKiller {
        fn kill(&self, pid: u32) -> std::io::Result<()> {
            if self.should_fail {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "permissao negada",
                ));
            }
            self.killed.store(true, Ordering::SeqCst);
            self.kill_pid.store(pid, Ordering::SeqCst);
            Ok(())
        }
    }

    fn test_policy(mode: Mode) -> Policy {
        let yaml = format!(
            r#"
mode: {}
filesystem:
  allow_read:
    - "/home/user/projects/**"
  allow_write:
    - "/home/user/projects/**"
  deny_always:
    - "**/.env"
network:
  allow_domains:
    - "api.anthropic.com"
  deny_all_else: true
syscalls:
  deny:
    - pattern: "ptrace"
      kill_on_deny: true
"#,
            if mode == Mode::Enforce { "enforce" } else { "monitor" }
        );
        Policy::from_yaml(&yaml).unwrap()
    }

    #[test]
    fn test_enforcer_allow_read() {
        let policy = test_policy(Mode::Enforce);
        let killer = MockKiller {
            killed: Arc::new(AtomicBool::new(false)),
            kill_pid: Arc::new(AtomicU32::new(0)),
            should_fail: false,
        };

        let enforcer = Enforcer::with_killer(policy, killer.clone());
        let event = Event {
            pid: 1234,
            event_type: EventType::Read,
            target: "/home/user/projects/main.rs".to_string(),
            resolved: false,
        };

        let action = enforcer.enforce(&event).unwrap();
        assert_eq!(action, Action::Allow);
        assert!(!killer.killed.load(Ordering::SeqCst));
    }

    #[test]
    fn test_enforcer_deny_enforce() {
        let policy = test_policy(Mode::Enforce);
        let killer = MockKiller {
            killed: Arc::new(AtomicBool::new(false)),
            kill_pid: Arc::new(AtomicU32::new(0)),
            should_fail: false,
        };

        let enforcer = Enforcer::with_killer(policy, killer.clone());
        let event = Event {
            pid: 1234,
            event_type: EventType::Read,
            target: "/home/user/projects/app/.env".to_string(),
            resolved: false,
        };

        let action = enforcer.enforce(&event).unwrap();
        assert_eq!(action, Action::Kill);
        assert!(killer.killed.load(Ordering::SeqCst));
        assert_eq!(killer.kill_pid.load(Ordering::SeqCst), 1234);
    }

    #[test]
    fn test_enforcer_deny_monitor() {
        let policy = test_policy(Mode::Monitor);
        let killer = MockKiller {
            killed: Arc::new(AtomicBool::new(false)),
            kill_pid: Arc::new(AtomicU32::new(0)),
            should_fail: false,
        };

        let enforcer = Enforcer::with_killer(policy, killer.clone());
        let event = Event {
            pid: 1234,
            event_type: EventType::Read,
            target: "/home/user/projects/app/.env".to_string(),
            resolved: false,
        };

        let action = enforcer.enforce(&event).unwrap();
        assert_eq!(action, Action::Log);
        assert!(!killer.killed.load(Ordering::SeqCst));
    }

    #[test]
    fn test_enforcer_kill_error() {
        let policy = test_policy(Mode::Enforce);
        let killer = MockKiller {
            killed: Arc::new(AtomicBool::new(false)),
            kill_pid: Arc::new(AtomicU32::new(0)),
            should_fail: true,
        };

        let enforcer = Enforcer::with_killer(policy, killer);
        let event = Event {
            pid: 1234,
            event_type: EventType::Read,
            target: "/home/user/projects/app/.env".to_string(),
            resolved: false,
        };

        let result = enforcer.enforce(&event);
        assert!(result.is_err());
        match result.err().unwrap() {
            EnforceError::KillFailed { pid, source } => {
                assert_eq!(pid, 1234);
                assert_eq!(source.kind(), std::io::ErrorKind::PermissionDenied);
            }
        }
    }

    #[test]
    fn test_enforcer_ipv6_unsupported() {
        let policy = test_policy(Mode::Enforce);
        let killer = MockKiller {
            killed: Arc::new(AtomicBool::new(false)),
            kill_pid: Arc::new(AtomicU32::new(0)),
            should_fail: false,
        };

        let enforcer = Enforcer::with_killer(policy, killer.clone());
        let event = Event {
            pid: 1234,
            event_type: EventType::Network,
            target: "<ipv6-nao-suportado>".to_string(),
            resolved: true,
        };

        let action = enforcer.enforce(&event).unwrap();
        assert_eq!(action, Action::Kill);
        assert!(killer.killed.load(Ordering::SeqCst));
    }

    #[test]
    fn test_enforcer_network_unresolved() {
        let policy = test_policy(Mode::Enforce);
        let killer = MockKiller {
            killed: Arc::new(AtomicBool::new(false)),
            kill_pid: Arc::new(AtomicU32::new(0)),
            should_fail: false,
        };

        let enforcer = Enforcer::with_killer(policy, killer.clone());
        let event = Event {
            pid: 1234,
            event_type: EventType::Network,
            target: "api.anthropic.com".to_string(),
            resolved: false, // Unresolved must be denied (zero trust)
        };

        let action = enforcer.enforce(&event).unwrap();
        assert_eq!(action, Action::Kill);
        assert!(killer.killed.load(Ordering::SeqCst));
    }

    #[test]
    fn test_enforcer_network_allowed() {
        let policy = test_policy(Mode::Enforce);
        let killer = MockKiller {
            killed: Arc::new(AtomicBool::new(false)),
            kill_pid: Arc::new(AtomicU32::new(0)),
            should_fail: false,
        };

        let enforcer = Enforcer::with_killer(policy, killer.clone());
        let event = Event {
            pid: 1234,
            event_type: EventType::Network,
            target: "api.anthropic.com".to_string(),
            resolved: true,
        };

        let action = enforcer.enforce(&event).unwrap();
        assert_eq!(action, Action::Allow);
        assert!(!killer.killed.load(Ordering::SeqCst));
    }

    #[test]
    fn test_enforcer_syscall_denied() {
        let policy = test_policy(Mode::Enforce);
        let killer = MockKiller {
            killed: Arc::new(AtomicBool::new(false)),
            kill_pid: Arc::new(AtomicU32::new(0)),
            should_fail: false,
        };

        let enforcer = Enforcer::with_killer(policy, killer.clone());
        let event = Event {
            pid: 1234,
            event_type: EventType::Syscall,
            target: "ptrace".to_string(),
            resolved: false,
        };

        let action = enforcer.enforce(&event).unwrap();
        assert_eq!(action, Action::Kill);
        assert!(killer.killed.load(Ordering::SeqCst));
    }

    #[test]
    fn test_enforcer_syscall_allowed() {
        let policy = test_policy(Mode::Enforce);
        let killer = MockKiller {
            killed: Arc::new(AtomicBool::new(false)),
            kill_pid: Arc::new(AtomicU32::new(0)),
            should_fail: false,
        };

        let enforcer = Enforcer::with_killer(policy, killer.clone());
        let event = Event {
            pid: 1234,
            event_type: EventType::Syscall,
            target: "openat".to_string(),
            resolved: false,
        };

        let action = enforcer.enforce(&event).unwrap();
        assert_eq!(action, Action::Allow);
        assert!(!killer.killed.load(Ordering::SeqCst));
    }

    #[test]
    fn test_enforcer_syscall_denied_no_kill() {
        let yaml = r#"
mode: enforce
filesystem:
  allow_read:
    - "**"
syscalls:
  deny:
    - "ptrace"
"#;
        let policy = Policy::from_yaml(yaml).unwrap();
        let killer = MockKiller {
            killed: Arc::new(AtomicBool::new(false)),
            kill_pid: Arc::new(AtomicU32::new(0)),
            should_fail: false,
        };

        let enforcer = Enforcer::with_killer(policy, killer.clone());
        let event = Event {
            pid: 1234,
            event_type: EventType::Syscall,
            target: "ptrace".to_string(),
            resolved: false,
        };

        let action = enforcer.enforce(&event).unwrap();
        assert_eq!(action, Action::Log);
        assert!(!killer.killed.load(Ordering::SeqCst));
    }
}
