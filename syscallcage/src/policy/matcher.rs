use regex::Regex;
use crate::policy::{Policy, PolicyError};

pub fn glob_to_regex(pattern: &str) -> Result<Regex, PolicyError> {
    let mut sb = String::new();
    sb.push('^');
    let chars: Vec<char> = pattern.chars().collect();
    let mut i = 0;
    let n = chars.len();
    while i < n {
        if i + 1 < n && chars[i] == '*' && chars[i + 1] == '*' {
            sb.push_str(".*");
            i += 2;
        } else if chars[i] == '*' {
            sb.push_str("[^/]*");
            i += 1;
        } else if chars[i] == '?' {
            sb.push_str("[^/]");
            i += 1;
        } else if chars[i] == '\\' {
            if i + 1 < n {
                sb.push_str(&regex::escape(&chars[i + 1].to_string()));
                i += 2;
            } else {
                sb.push_str(&regex::escape("\\"));
                i += 1;
            }
        } else {
            sb.push_str(&regex::escape(&chars[i].to_string()));
            i += 1;
        }
    }
    sb.push('$');

    Regex::new(&sb).map_err(|source| PolicyError::InvalidGlob {
        pattern: pattern.to_string(),
        source,
    })
}

impl Policy {
    pub fn path_allowed(&self, path: &str, for_write: bool) -> bool {
        for re in &self.compiled_deny {
            if re.is_match(path) {
                return false;
            }
        }

        let allow_list = if for_write {
            &self.compiled_allow_write
        } else {
            &self.compiled_allow_read
        };

        for re in allow_list {
            if re.is_match(path) {
                return true;
            }
        }

        false
    }

    pub fn domain_allowed(&self, domain: &str) -> bool {
        for allowed in &self.allow_domains {
            if allowed.eq_ignore_ascii_case(domain) {
                return true;
            }
        }
        !self.deny_all_else
    }
}
