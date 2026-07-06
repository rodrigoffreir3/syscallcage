// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use crate::logging;

#[derive(Serialize)]
pub struct GeneratedPolicy {
    pub mode: String,
    pub filesystem: GeneratedFilesystem,
    pub network: GeneratedNetwork,
    pub syscalls: GeneratedSyscalls,
}

#[derive(Serialize)]
pub struct GeneratedFilesystem {
    pub allow_read: Vec<String>,
    pub allow_write: Vec<String>,
    pub deny_always: Vec<String>,
}

#[derive(Serialize)]
pub struct GeneratedNetwork {
    pub allow_domains: Vec<String>,
    pub deny_all_else: bool,
}

#[derive(Serialize)]
pub struct GeneratedSyscalls {
    pub deny: Vec<String>,
}

const MANDATORY_DENY_ALWAYS: &[&str] = &[
    "**/.env",
    "**/.ssh/**",
    "**/id_rsa*",
    "**/*.pem",
];

const MANDATORY_DENY_SYSCALLS: &[&str] = &[
    "execve:/bin/sh",
    "execve:/bin/bash",
    "ptrace",
];

#[derive(Deserialize, Debug)]
struct LogLine {
    event_type: Option<String>,
    target: Option<String>,
    action: Option<String>,
}

/// Filtra paths sensíveis que nunca devem entrar nas allowlists.
fn is_sensitive_path(path: &str) -> bool {
    let lower = path.to_lowercase();
    lower.contains(".env") || lower.contains(".ssh") || lower.contains("id_rsa") || lower.ends_with(".pem")
}

/// Agrupa caminhos observados no menor conjunto de padrões glob que os cobre.
pub fn generalize_paths(paths: &[String]) -> Vec<String> {
    if paths.is_empty() {
        return Vec::new();
    }

    // 1. Normalizar e ordenar caminhos
    let mut normalized_paths: Vec<PathBuf> = paths.iter()
        .map(|p| Path::new(p).to_path_buf())
        .collect();
    normalized_paths.sort();
    normalized_paths.dedup();

    // 2. Agrupar por cluster key (primeiros 2 componentes significativos)
    let mut groups: HashMap<PathBuf, Vec<PathBuf>> = HashMap::new();

    for path in normalized_paths {
        let mut components = path.components();
        let mut cluster_key = PathBuf::new();
        
        // Adiciona a raiz /
        if let Some(c) = components.next() {
            cluster_key.push(c.as_os_str());
        }
        // Adiciona o primeiro nível (ex: home)
        if let Some(c) = components.next() {
            cluster_key.push(c.as_os_str());
        }
        // Adiciona o segundo nível (ex: user) se houver componentes subsequentes
        if let Some(c) = components.next() {
            let next_peek = components.clone().next();
            if next_peek.is_some() {
                cluster_key.push(c.as_os_str());
            }
        }
        groups.entry(cluster_key).or_default().push(path);
    }

    let mut globs = Vec::new();

    for (_key, group_paths) in groups {
        if group_paths.is_empty() {
            continue;
        }

        if group_paths.len() == 1 {
            // Apenas 1 caminho no grupo: geramos parent_dir/**
            let p = &group_paths[0];
            if let Some(parent) = p.parent() {
                let parent_str = parent.to_string_lossy();
                if parent_str == "/" {
                    globs.push("/**".to_string());
                } else {
                    globs.push(format!("{}/**", parent_str));
                }
            } else {
                globs.push("/**".to_string());
            }
            continue;
        }

        // Múltiplos caminhos no grupo: encontrar o ancestral comum mais longo
        let mut common = group_paths[0].clone();
        for other in &group_paths[1..] {
            let mut new_common = PathBuf::new();
            for (c1, c2) in common.components().zip(other.components()) {
                if c1 == c2 {
                    new_common.push(c1.as_os_str());
                } else {
                    break;
                }
            }
            common = new_common;
        }

        let common_str = common.to_string_lossy().into_owned();
        if common_str.is_empty() || common_str == "/" {
            // Se o ancestral comum virar a raiz, gera parent individual para cada um
            for p in group_paths {
                if let Some(parent) = p.parent() {
                    let parent_str = parent.to_string_lossy();
                    let entry = if parent_str == "/" { "/**".to_string() } else { format!("{}/**", parent_str) };
                    globs.push(entry);
                }
            }
        } else {
            // Se common for igual a um dos caminhos, pegamos o parent dele
            let is_file = group_paths.iter().any(|p| *p == common);
            if is_file {
                if let Some(parent) = common.parent() {
                    let parent_str = parent.to_string_lossy();
                    globs.push(format!("{}/**", parent_str));
                } else {
                    globs.push(format!("{}/**", common_str));
                }
            } else {
                globs.push(format!("{}/**", common_str));
            }
        }
    }

    globs.sort();
    globs.dedup();
    globs
}

/// Gera a política a partir de um log de eventos.
pub fn run_generator(from_log: &Path, output: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let file = File::open(from_log)?;
    let reader = BufReader::new(file);

    let mut raw_reads = Vec::new();
    let mut raw_writes = Vec::new();
    let mut raw_domains = Vec::new();
    let mut raw_syscalls = Vec::new();
    let mut event_count = 0;

    for (line_num, line_res) in reader.lines().enumerate() {
        let line = match line_res {
            Ok(l) => l,
            Err(e) => {
                logging::log(logging::Entry {
                    timestamp: logging::get_timestamp(),
                    level: "warn",
                    component: "policy_generator",
                    message: &format!("erro ao ler linha {} do log: {}", line_num + 1, e),
                    pid: None,
                    event_type: None,
                    target: None,
                    action: None,
                });
                continue;
            }
        };

        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        let log_line: LogLine = match serde_json::from_str(trimmed) {
            Ok(val) => val,
            Err(e) => {
                logging::log(logging::Entry {
                    timestamp: logging::get_timestamp(),
                    level: "warn",
                    component: "policy_generator",
                    message: &format!("linha {} malformada no log: {}", line_num + 1, e),
                    pid: None,
                    event_type: None,
                    target: None,
                    action: None,
                });
                continue;
            }
        };

        event_count += 1;

        if let (Some(et), Some(target)) = (log_line.event_type, log_line.target) {
            match et.to_lowercase().as_str() {
                "read" => {
                    if !is_sensitive_path(&target) {
                        raw_reads.push(target);
                    }
                }
                "write" => {
                    if !is_sensitive_path(&target) {
                        raw_writes.push(target);
                    }
                }
                "network" => {
                    raw_domains.push(target);
                }
                "syscall" => {
                    raw_syscalls.push(target);
                }
                _ => {}
            }
        }
    }

    // 1. Generalizar caminhos do filesystem
    let allow_read = generalize_paths(&raw_reads);
    let allow_write = generalize_paths(&raw_writes);

    // 2. Processar domínios
    let mut allow_domains = raw_domains;
    allow_domains.sort();
    allow_domains.dedup();

    // 3. Processar syscalls
    let mut deny_syscalls: Vec<String> = MANDATORY_DENY_SYSCALLS.iter()
        .map(|s| s.to_string())
        .collect();

    // Se no log apareceu syscall perigosa, garante que ela está bloqueada.
    // Syscalls observadas fora da lista de risco não geram regra alguma — nem allow nem deny;
    // ficam sob o comportamento padrão da política.
    for sys in raw_syscalls {
        if MANDATORY_DENY_SYSCALLS.iter().any(|&m| sys.contains(m) || m.contains(&sys)) {
            deny_syscalls.push(sys);
        }
    }
    deny_syscalls.sort();
    deny_syscalls.dedup();

    // 4. Montar a política gerada
    let generated = GeneratedPolicy {
        mode: "enforce".to_string(),
        filesystem: GeneratedFilesystem {
            allow_read,
            allow_write,
            deny_always: MANDATORY_DENY_ALWAYS.iter().map(|s| s.to_string()).collect(),
        },
        network: GeneratedNetwork {
            allow_domains,
            deny_all_else: true,
        },
        syscalls: GeneratedSyscalls {
            deny: deny_syscalls,
        },
    };

    // 5. Serializar para YAML
    let yaml_content = serde_yaml::to_string(&generated)?;

    // 6. Criar cabeçalho explicativo
    let log_filename = from_log.file_name()
        .map(|f| f.to_string_lossy().into_owned())
        .unwrap_or_else(|| "sessao.jsonl".to_string());
    
    let timestamp = logging::get_timestamp();

    let header = format!(
        "# Política gerada automaticamente por `syscallcage generate-policy`\n\
         # a partir de: {} ({} eventos analisados)\n\
         # Gerado em: {}\n\
         #\n\
         # REVISE ANTES DE USAR EM PRODUÇÃO. Isto reflete o que foi OBSERVADO\n\
         # numa sessão, não uma auditoria de segurança. Confirme que os paths e\n\
         # domínios abaixo fazem sentido para o seu caso de uso antes de rodar\n\
         # em modo enforce.\n\n",
        log_filename, event_count, timestamp
    );

    let final_content = format!("{}{}", header, yaml_content);

    // 7. Escrever no arquivo
    std::fs::write(output, final_content)?;

    logging::log(logging::Entry {
        timestamp: logging::get_timestamp(),
        level: "info",
        component: "policy_generator",
        message: &format!("Política gerada com sucesso e salva em {:?}", output),
        pid: None,
        event_type: None,
        target: None,
        action: None,
    });

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn get_temp_filepath() -> PathBuf {
        let dur = std::time::SystemTime::now().duration_since(std::time::SystemTime::UNIX_EPOCH).unwrap();
        let name = format!("test_policy_gen_{}_{}", dur.as_secs(), dur.subsec_nanos());
        std::env::temp_dir().join(name)
    }

    #[test]
    fn test_generalize_paths_same_dir() {
        let paths = vec![
            "/home/user/proj/a.rs".to_string(),
            "/home/user/proj/b.rs".to_string(),
            "/home/user/proj/sub/c.rs".to_string(),
        ];
        let result = generalize_paths(&paths);
        assert_eq!(result, vec!["/home/user/proj/**".to_string()]);
    }

    #[test]
    fn test_generalize_paths_different_dirs() {
        let paths = vec![
            "/home/a/x".to_string(),
            "/tmp/b/y".to_string(),
        ];
        let result = generalize_paths(&paths);
        assert_eq!(result, vec!["/home/a/**".to_string(), "/tmp/b/**".to_string()]);
    }

    #[test]
    fn test_is_sensitive_path() {
        assert!(is_sensitive_path("/path/to/.env"));
        assert!(is_sensitive_path("/home/user/.ssh/id_rsa"));
        assert!(is_sensitive_path("/home/user/my_key.pem"));
        assert!(!is_sensitive_path("/home/user/projects/main.rs"));
    }

    #[test]
    fn test_run_generator_skips_sensitive_paths_and_handles_corrupted_json() {
        let log_path = get_temp_filepath();
        let out_path = get_temp_filepath();

        {
            let mut log_file = File::create(&log_path).unwrap();
            // Escreve alguns eventos válidos, um sensível e um corrompido
            writeln!(log_file, "{{\"timestamp\":\"2026-07-06T04:44:15Z\",\"level\":\"info\",\"component\":\"enforcer\",\"message\":\"allowed\",\"event_type\":\"read\",\"target\":\"/home/user/proj/a.rs\"}}").unwrap();
            writeln!(log_file, "{{\"timestamp\":\"2026-07-06T04:44:15Z\",\"level\":\"info\",\"component\":\"enforcer\",\"message\":\"allowed\",\"event_type\":\"read\",\"target\":\"/home/user/proj/.env\"}}").unwrap();
            writeln!(log_file, "this is corrupted json").unwrap();
            writeln!(log_file, "{{\"timestamp\":\"2026-07-06T04:44:15Z\",\"level\":\"info\",\"component\":\"enforcer\",\"message\":\"allowed\",\"event_type\":\"write\",\"target\":\"/home/user/proj/output.log\"}}").unwrap();
        }

        run_generator(&log_path, &out_path).unwrap();

        let output_content = std::fs::read_to_string(&out_path).unwrap();
        
        // Limpa arquivos de teste
        let _ = std::fs::remove_file(&log_path);
        let _ = std::fs::remove_file(&out_path);

        // Deve conter o cabeçalho de aviso
        assert!(output_content.contains("Política gerada automaticamente"));
        
        // Parse estruturado para asserções fortes e precisas
        let yaml_val: serde_json::Value = serde_yaml::from_str(&output_content).unwrap();
        assert_eq!(yaml_val["mode"], "enforce");

        let allow_read = yaml_val["filesystem"]["allow_read"].as_array().unwrap();
        assert!(allow_read.iter().any(|v| v.as_str() == Some("/home/user/proj/**")));

        let allow_write = yaml_val["filesystem"]["allow_write"].as_array().unwrap();
        assert!(allow_write.iter().any(|v| v.as_str() == Some("/home/user/proj/**")));

        let deny_always = yaml_val["filesystem"]["deny_always"].as_array().unwrap();
        assert!(deny_always.iter().any(|v| v.as_str() == Some("**/.env")));

        // NÃO deve conter liberação para .env nas allowlists
        assert!(!allow_read.iter().any(|v| v.as_str().unwrap().contains(".env")));
        assert!(!allow_write.iter().any(|v| v.as_str().unwrap().contains(".env")));

        let deny_syscalls = yaml_val["syscalls"]["deny"].as_array().unwrap();
        assert!(deny_syscalls.iter().any(|v| v.as_str() == Some("execve:/bin/sh")));
    }
}
