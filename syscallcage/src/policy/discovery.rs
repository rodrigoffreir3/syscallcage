use std::path::{Path, PathBuf};
use std::os::unix::fs::MetadataExt;
use std::fs::Metadata;
use thiserror::Error;
use crate::logging;

#[derive(Error, Debug)]
pub enum DiscoveryError {
    #[error("arquivo de política não encontrado")]
    NotFound,
    #[error("erro de I/O ao procurar política: {0}")]
    Io(#[from] std::io::Error),
    #[error("política insegura recusada ({path}): {reason}")]
    InsecurePolicy {
        path: String,
        reason: String,
    },
}

/// Procura `.syscallcage.yaml` a partir do diretório atual, subindo até a
/// raiz do projeto. A subida PARA no primeiro diretório que contenha `.git`
/// (inclusive), e NUNCA vai além dele.
pub fn discover_policy(start: &Path) -> Result<Option<PathBuf>, DiscoveryError> {
    let mut current = start.to_path_buf();

    loop {
        let candidate = current.join(".syscallcage.yaml");
        if candidate.exists() {
            validate_discovered_policy(&candidate)?;
            return Ok(Some(candidate));
        }

        // Verifica se é raiz do git
        if current.join(".git").exists() {
            break;
        }

        if !current.pop() {
            break; // chegou à raiz do sistema de arquivos
        }
    }

    Ok(None)
}

/// Recusa arquivo de política descoberto automaticamente que não satisfaça
/// as garantias mínimas de confiança. Zero trust.
fn validate_discovered_policy(path: &Path) -> Result<(), DiscoveryError> {
    let meta = std::fs::symlink_metadata(path)?;

    // 1. É arquivo regular
    if !meta.is_file() {
        return Err(DiscoveryError::InsecurePolicy {
            path: path.display().to_string(),
            reason: "não é um arquivo regular (pode ser um symlink malicioso)".to_string(),
        });
    }

    // 2. Não é gravável por "others" (o+w)
    let mode = meta.mode();
    if mode & 0o002 != 0 {
        return Err(DiscoveryError::InsecurePolicy {
            path: path.display().to_string(),
            reason: "o arquivo é gravável por outros usuários (permissão o+w)".to_string(),
        });
    }

    // 3. Dono é o usuário atual OU root
    let uid = meta.uid();
    let euid = unsafe { libc::geteuid() };
    
    let sudo_uid = std::env::var("SUDO_UID")
        .ok()
        .and_then(|s| s.parse::<u32>().ok());

    if uid != euid && uid != 0 && Some(uid) != sudo_uid {
        return Err(DiscoveryError::InsecurePolicy {
            path: path.display().to_string(),
            reason: format!("dono do arquivo (uid: {}) não é root nem o usuário atual (uid: {}, sudo_uid: {:?})", uid, euid, sudo_uid),
        });
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn test_validate_discovered_policy_world_writable() {
        let temp_dir = std::env::temp_dir().join(format!("syscallcage_test_discovery_{}", std::process::id()));
        fs::create_dir_all(&temp_dir).unwrap();
        let file_path = temp_dir.join(".syscallcage.yaml");
        fs::write(&file_path, "mode: enforce").unwrap();

        // Faz o arquivo ser o+w
        let mut perms = fs::metadata(&file_path).unwrap().permissions();
        perms.set_mode(0o666); // r+w para todos
        fs::set_permissions(&file_path, perms).unwrap();

        let result = validate_discovered_policy(&file_path);
        assert!(matches!(result, Err(DiscoveryError::InsecurePolicy { .. })));
        if let Err(DiscoveryError::InsecurePolicy { reason, .. }) = result {
            assert!(reason.contains("o+w"));
        }

        fs::remove_dir_all(&temp_dir).unwrap();
    }

    #[test]
    fn test_discover_policy_boundary() {
        let temp_dir = std::env::temp_dir().join(format!("syscallcage_test_boundary_{}", std::process::id()));
        let git_dir = temp_dir.join("project");
        let sub_dir = git_dir.join("src").join("module");
        
        fs::create_dir_all(&sub_dir).unwrap();
        fs::create_dir_all(git_dir.join(".git")).unwrap();
        
        // Politica na raiz do temp_dir (fora do "git", subindo a árvore)
        let outer_policy = temp_dir.join(".syscallcage.yaml");
        fs::write(&outer_policy, "mode: enforce").unwrap();

        // Define permissoes corretas para outer_policy
        let mut perms = fs::metadata(&outer_policy).unwrap().permissions();
        perms.set_mode(0o600); // Somente owner
        fs::set_permissions(&outer_policy, perms).unwrap();
        
        // Se a busca começar em sub_dir, ela sobe até `project` (.git), não acha nada e para.
        // Não deve achar `outer_policy` porque parou no .git
        let discovered = discover_policy(&sub_dir).unwrap();
        assert!(discovered.is_none());

        // Coloca politica no git_dir e tenta de novo
        let inner_policy = git_dir.join(".syscallcage.yaml");
        fs::write(&inner_policy, "mode: enforce").unwrap();
        let mut perms = fs::metadata(&inner_policy).unwrap().permissions();
        perms.set_mode(0o600); // Somente owner
        fs::set_permissions(&inner_policy, perms).unwrap();

        let discovered2 = discover_policy(&sub_dir).unwrap();
        assert!(discovered2.is_some());
        assert_eq!(discovered2.unwrap(), inner_policy);

        fs::remove_dir_all(&temp_dir).unwrap();
    }
}
