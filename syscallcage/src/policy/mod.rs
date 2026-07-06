use regex::Regex;
use serde::Deserialize;
use thiserror::Error;

pub mod matcher;

#[derive(Debug, Error)]
pub enum PolicyError {
    #[error("falha ao ler arquivo de política: {0}")]
    Io(#[from] std::io::Error),
    #[error("yaml inválido: {0}")]
    Yaml(#[from] serde_yaml::Error),
    #[error("regex inválido em '{pattern}': {source}")]
    InvalidGlob { pattern: String, source: regex::Error },
    #[error("mode deve ser 'enforce' ou 'monitor', recebido: '{0}'")]
    InvalidMode(String),
    #[error("política sem nenhum allow_read/allow_write -- provável erro de configuração")]
    EmptyAllowList,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    Enforce,
    Monitor,
}

#[derive(Debug, Deserialize, Default)]
struct RawFilesystem {
    #[serde(default)]
    allow_read: Vec<String>,
    #[serde(default)]
    allow_write: Vec<String>,
    #[serde(default)]
    deny_always: Vec<String>,
}

#[derive(Debug, Deserialize, Default)]
struct RawNetwork {
    #[serde(default)]
    allow_domains: Vec<String>,
    #[serde(default)]
    deny_all_else: bool,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(untagged)]
pub enum SyscallDenyRule {
    Simple(String),
    Structured {
        pattern: String,
        #[serde(default)]
        kill_on_deny: bool,
    },
}

#[derive(Debug, Clone)]
pub struct SyscallRule {
    pub pattern: String,
    pub kill_on_deny: bool,
}

#[derive(Debug, Deserialize, Default)]
struct RawSyscalls {
    #[serde(default)]
    deny: Vec<SyscallDenyRule>,
}

#[derive(Debug, Deserialize)]
struct RawPolicy {
    mode: String,
    #[serde(default)]
    filesystem: RawFilesystem,
    #[serde(default)]
    network: RawNetwork,
    #[serde(default)]
    syscalls: RawSyscalls,
}

/// Política já validada e com todos os padrões glob pré-compilados.
/// Não existe forma de construir isso sem passar pela compilação --
/// o construtor privado garante que uma Policy "existe" apenas se
/// já está pronta para responder consultas corretamente.
#[derive(Clone)]
pub struct Policy {
    mode: Mode,
    compiled_deny: Vec<Regex>,
    compiled_allow_read: Vec<Regex>,
    compiled_allow_write: Vec<Regex>,
    allow_domains: Vec<String>,
    deny_all_else: bool,
    pub deny_syscalls: Vec<SyscallRule>,
    pub raw_deny_always: Vec<String>,
    pub raw_allow_read: Vec<String>,
    pub raw_allow_write: Vec<String>,
}

impl Policy {
    /// Único ponto de entrada público para obter uma Policy a partir de
    /// arquivo. Lê, parseia, valida E compila antes de retornar --
    /// impossível obter uma Policy em estado parcial.
    pub fn load(path: &std::path::Path) -> Result<Self, PolicyError> {
        let raw_bytes = std::fs::read(path)?;
        let yaml_str = std::str::from_utf8(&raw_bytes)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        Self::from_yaml(yaml_str)
    }

    /// Constrói e valida uma política diretamente de uma string YAML.
    pub fn from_yaml(yaml_str: &str) -> Result<Self, PolicyError> {
        let raw: RawPolicy = serde_yaml::from_str(yaml_str)?;
        let mode = match raw.mode.as_str() {
            "enforce" => Mode::Enforce,
            "monitor" => Mode::Monitor,
            other => return Err(PolicyError::InvalidMode(other.to_string())),
        };

        if raw.filesystem.allow_read.is_empty() && raw.filesystem.allow_write.is_empty() {
            return Err(PolicyError::EmptyAllowList);
        }

        let compiled_deny = raw.filesystem.deny_always.iter()
            .map(|p| matcher::glob_to_regex(p))
            .collect::<Result<Vec<_>, _>>()?;

        let compiled_allow_read = raw.filesystem.allow_read.iter()
            .map(|p| matcher::glob_to_regex(p))
            .collect::<Result<Vec<_>, _>>()?;

        let compiled_allow_write = raw.filesystem.allow_write.iter()
            .map(|p| matcher::glob_to_regex(p))
            .collect::<Result<Vec<_>, _>>()?;

        let deny_syscalls = raw.syscalls.deny.into_iter()
            .map(|r| match r {
                SyscallDenyRule::Simple(s) => SyscallRule { pattern: s, kill_on_deny: false },
                SyscallDenyRule::Structured { pattern, kill_on_deny } => SyscallRule { pattern, kill_on_deny },
            })
            .collect();

        let raw_deny_always = raw.filesystem.deny_always.clone();
        let raw_allow_read = raw.filesystem.allow_read.clone();
        let raw_allow_write = raw.filesystem.allow_write.clone();

        Ok(Self {
            mode,
            compiled_deny,
            compiled_allow_read,
            compiled_allow_write,
            allow_domains: raw.network.allow_domains,
            deny_all_else: raw.network.deny_all_else,
            deny_syscalls,
            raw_deny_always,
            raw_allow_read,
            raw_allow_write,
        })
    }

    pub fn mode(&self) -> Mode {
        self.mode
    }

    pub fn syscall_denied(&self, syscall: &str) -> bool {
        self.deny_syscalls.iter().any(|r| {
            if r.pattern == syscall {
                return true;
            }
            if !r.pattern.contains(':') && syscall.starts_with(&format!("{}:", r.pattern)) {
                return true;
            }
            false
        })
    }

    pub fn should_kill_on_syscall_deny(&self, syscall: &str) -> bool {
        self.deny_syscalls.iter()
            .find(|r| {
                if r.pattern == syscall {
                    return true;
                }
                if !r.pattern.contains(':') && syscall.starts_with(&format!("{}:", r.pattern)) {
                    return true;
                }
                false
            })
            .map(|r| r.kill_on_deny)
            .unwrap_or(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_deny_always_wins() {
        let yaml = r#"
mode: enforce
filesystem:
  allow_read:
    - "/home/user/projects/**"
  deny_always:
    - "/home/user/projects/app/.env"
"#;
        let policy = Policy::from_yaml(yaml).unwrap();
        // Path in allow_read but also deny_always -> should be denied
        assert!(!policy.path_allowed("/home/user/projects/app/.env", false));
        // Normal path in allow_read -> should be allowed
        assert!(policy.path_allowed("/home/user/projects/app/main.rs", false));
    }

    #[test]
    fn test_glob_starting_with_double_star() {
        let yaml = r#"
mode: enforce
filesystem:
  allow_read:
    - "/home/user/**"
  deny_always:
    - "**/.env"
"#;
        let policy = Policy::from_yaml(yaml).unwrap();
        assert!(!policy.path_allowed("/home/user/projects/app/.env", false));
        assert!(!policy.path_allowed("/other/.env", false));
        assert!(policy.path_allowed("/home/user/main.rs", false));
    }

    #[test]
    fn test_zero_trust_default_deny() {
        let yaml = r#"
mode: enforce
filesystem:
  allow_read:
    - "/home/user/**"
"#;
        let policy = Policy::from_yaml(yaml).unwrap();
        // Outside allowed directory -> should be denied
        assert!(!policy.path_allowed("/etc/passwd", false));
    }

    #[test]
    fn test_domain_allowed_with_deny_all_else() {
        // deny_all_else: true
        let yaml = r#"
mode: enforce
filesystem:
  allow_read:
    - "**"
network:
  allow_domains:
    - "api.anthropic.com"
  deny_all_else: true
"#;
        let policy = Policy::from_yaml(yaml).unwrap();
        assert!(policy.domain_allowed("api.anthropic.com"));
        assert!(policy.domain_allowed("API.ANTHROPIC.COM")); // Case insensitive
        assert!(!policy.domain_allowed("google.com"));

        // deny_all_else: false
        let yaml2 = r#"
mode: enforce
filesystem:
  allow_read:
    - "**"
network:
  allow_domains:
    - "api.anthropic.com"
  deny_all_else: false
"#;
        let policy2 = Policy::from_yaml(yaml2).unwrap();
        assert!(policy2.domain_allowed("api.anthropic.com"));
        assert!(policy2.domain_allowed("google.com"));
    }

    #[test]
    fn test_generic_syscall_checks() {
        let yaml = r#"
mode: enforce
filesystem:
  allow_read:
    - "**"
syscalls:
  deny:
    - "ptrace"
    - pattern: "execve:/bin/sh"
      kill_on_deny: true
"#;
        let policy = Policy::from_yaml(yaml).unwrap();
        assert!(policy.syscall_denied("ptrace"));
        assert!(policy.syscall_denied("ptrace:PTRACE_ATTACH"));
        assert!(!policy.should_kill_on_syscall_deny("ptrace"));
        
        assert!(policy.syscall_denied("execve:/bin/sh"));
        assert!(policy.should_kill_on_syscall_deny("execve:/bin/sh"));
        assert!(!policy.syscall_denied("execve:/bin/ls"));
    }

    #[test]
    fn test_invalid_mode_returns_err() {
        let yaml = r#"
mode: yolo
filesystem:
  allow_read:
    - "**"
"#;
        let res = Policy::from_yaml(yaml);
        assert!(res.is_err());
        match res.err().unwrap() {
            PolicyError::InvalidMode(m) => assert_eq!(m, "yolo"),
            _ => panic!("expected PolicyError::InvalidMode"),
        }
    }

    #[test]
    fn test_empty_allow_list_returns_err() {
        let yaml = r#"
mode: enforce
filesystem:
  deny_always:
    - "**/.env"
"#;
        let res = Policy::from_yaml(yaml);
        assert!(res.is_err());
        assert!(matches!(res.err().unwrap(), PolicyError::EmptyAllowList));
    }
}
