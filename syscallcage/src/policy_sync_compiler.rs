// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

use crate::policy::Policy;
use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum SyncCompileError {
    #[error("glob não suportado no modo síncrono: '{0}' (apenas prefixos de diretório são suportados)")]
    UnsupportedGlob(String),
    #[error("limite máximo de 16 regras excedido para o mapa síncrono")]
    LimitExceeded,
}

pub struct SyncCompiledPolicy {
    pub allow_read_prefixes: Vec<[u8; 128]>,
    pub allow_write_prefixes: Vec<[u8; 128]>,
    pub deny_always_prefixes: Vec<[u8; 128]>,
    pub deny_syscalls_rules: Vec<([u8; 128], bool)>, // (pattern, kill_on_deny)
}

/// Helper para converter string de prefixo em [u8; 128] limpo, preenchido com zeros.
fn string_to_bytes_128(s: &str) -> [u8; 128] {
    let mut bytes = [0u8; 128];
    let s_bytes = s.as_bytes();
    let len = std::cmp::min(s_bytes.len(), 127);
    bytes[..len].copy_from_slice(&s_bytes[..len]);
    bytes
}

/// Helper para extrair prefixo literal de um padrão.
/// Retorna Ok(prefixo) se puder ser expresso como prefixo puro, ou Err(()) caso contrário.
fn extract_prefix(pattern: &str) -> Result<String, ()> {
    // Se o padrão for vazio, é inválido
    if pattern.is_empty() {
        return Err(());
    }

    // Se o padrão for "**" ou "**/*", ele significa "tudo", o que representamos como o prefixo "/"
    if pattern == "**" || pattern == "**/*" {
        return Ok("/".to_string());
    }

    // Padrões síncronos devem começar com "/"
    if !pattern.starts_with('/') {
        return Err(());
    }

    // Verifica se contém curingas no meio
    let mut clean_part = pattern;
    if pattern.ends_with("/**") {
        clean_part = &pattern[..pattern.len() - 3];
    } else if pattern.ends_with("/**/") {
        clean_part = &pattern[..pattern.len() - 4];
    } else if pattern.ends_with("**") {
        clean_part = &pattern[..pattern.len() - 2];
    } else if pattern.ends_with("/*") {
        clean_part = &pattern[..pattern.len() - 2];
    }

    // Se a parte limpa contiver qualquer caractere curinga, ela não é um prefixo puro
    if clean_part.contains('*') || clean_part.contains('?') || clean_part.contains('[') {
        return Err(());
    }

    // Garante que termina com "/" para representar diretório, exceto se for arquivo literal específico
    let mut result = clean_part.to_string();
    if pattern.ends_with("/**") || pattern.ends_with("/*") || pattern.ends_with("**") {
        if !result.ends_with('/') {
            result.push('/');
        }
    }

    Ok(result)
}

/// Verifica se o padrão de deny é uma das regras estáticas sensíveis tratadas nativamente pelo hook eBPF.
fn is_static_security_rule(pattern: &str) -> bool {
    let p = pattern.trim();
    p == "**/.env" || p == ".env" || p == "**/.ssh/**" || p == "**/id_rsa*" || p == "**/*.pem"
}

pub fn try_compile_for_sync(policy: &Policy) -> Result<SyncCompiledPolicy, SyncCompileError> {
    let mut allow_read_prefixes = Vec::new();
    let mut allow_write_prefixes = Vec::new();
    let mut deny_always_prefixes = Vec::new();
    let mut deny_syscalls_rules = Vec::new();

    // 1. Compilar allow_read
    for r in &policy.raw_allow_read {
        if let Ok(prefix) = extract_prefix(r) {
            allow_read_prefixes.push(string_to_bytes_128(&prefix));
        } else {
            return Err(SyncCompileError::UnsupportedGlob(r.clone()));
        }
    }

    // 2. Compilar allow_write
    for w in &policy.raw_allow_write {
        if let Ok(prefix) = extract_prefix(w) {
            allow_write_prefixes.push(string_to_bytes_128(&prefix));
        } else {
            return Err(SyncCompileError::UnsupportedGlob(w.clone()));
        }
    }

    // 3. Compilar deny_always (pulando regras sensíveis obrigatórias tratadas no eBPF)
    for d in &policy.raw_deny_always {
        if is_static_security_rule(d) {
            continue;
        }
        if let Ok(prefix) = extract_prefix(d) {
            deny_always_prefixes.push(string_to_bytes_128(&prefix));
        } else {
            return Err(SyncCompileError::UnsupportedGlob(d.clone()));
        }
    }

    // 4. Compilar deny_syscalls
    for s in &policy.deny_syscalls {
        // As syscalls denylisted no eBPF LSM síncrono devem começar com "execve:".
        // Qualquer outra syscall fará o compilador cair para o modo Reactive.
        // O padrão também não deve conter curingas do tipo glob.
        if s.pattern.contains('*') || s.pattern.contains('?') || s.pattern.contains('[') {
            return Err(SyncCompileError::UnsupportedGlob(s.pattern.clone()));
        }
        if !s.pattern.starts_with("execve:") {
            return Err(SyncCompileError::UnsupportedGlob(s.pattern.clone()));
        }
        deny_syscalls_rules.push((string_to_bytes_128(&s.pattern), s.kill_on_deny));
    }

    // 5. Validar limites do eBPF (max 16 regras em cada mapa)
    if allow_read_prefixes.len() > 16 
        || allow_write_prefixes.len() > 16 
        || deny_always_prefixes.len() > 16 
        || deny_syscalls_rules.len() > 16 
    {
        return Err(SyncCompileError::LimitExceeded);
    }

    Ok(SyncCompiledPolicy {
        allow_read_prefixes,
        allow_write_prefixes,
        deny_always_prefixes,
        deny_syscalls_rules,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::Mode;

    fn make_test_policy(allow_read: Vec<&str>, allow_write: Vec<&str>, deny_always: Vec<&str>, deny_syscalls: Vec<(&str, bool)>) -> Policy {
        let mut yaml = "mode: enforce\nfilesystem:\n  allow_read:\n".to_string();
        for r in allow_read {
            yaml.push_str(&format!("    - \"{}\"\n", r));
        }
        yaml.push_str("  allow_write:\n");
        for w in allow_write {
            yaml.push_str(&format!("    - \"{}\"\n", w));
        }
        yaml.push_str("  deny_always:\n");
        for d in deny_always {
            yaml.push_str(&format!("    - \"{}\"\n", d));
        }
        yaml.push_str("syscalls:\n  deny:\n");
        for (s, k) in deny_syscalls {
            yaml.push_str(&format!("    - pattern: \"{}\"\n      kill_on_deny: {}\n", s, k));
        }
        Policy::from_yaml(&yaml).unwrap()
    }

    #[test]
    fn test_sync_compiler_success() {
        let policy = make_test_policy(
            vec!["/home/user/**", "/etc/hosts"],
            vec!["/tmp/"],
            vec!["**/.env", "/tmp/forbidden/"],
            vec![("execve:/bin/sh", false)]
        );

        let compiled = try_compile_for_sync(&policy).unwrap();
        assert_eq!(compiled.allow_read_prefixes.len(), 2);
        assert_eq!(compiled.allow_write_prefixes.len(), 1);
        assert_eq!(compiled.deny_always_prefixes.len(), 1); // **/.env foi pulado pois é estático
        assert_eq!(compiled.deny_syscalls_rules.len(), 1);
        
        // Verifica bytes convertidos
        assert_eq!(&compiled.allow_write_prefixes[0][..5], b"/tmp/");
    }

    #[test]
    fn test_sync_compiler_unsupported_glob() {
        let policy = make_test_policy(
            vec!["/home/*/projects/**"], // curinga no meio
            vec![],
            vec![],
            vec![]
        );

        let res = try_compile_for_sync(&policy);
        assert!(res.is_err());
        assert_eq!(res.err().unwrap(), SyncCompileError::UnsupportedGlob("/home/*/projects/**".to_string()));
    }

    #[test]
    fn test_sync_compiler_unsupported_syscall() {
        let policy = make_test_policy(
            vec!["/tmp/"],
            vec![],
            vec![],
            vec![("ptrace", true)]
        );

        let res = try_compile_for_sync(&policy);
        assert!(res.is_err());
        assert_eq!(res.err().unwrap(), SyncCompileError::UnsupportedGlob("ptrace".to_string()));
    }
}
