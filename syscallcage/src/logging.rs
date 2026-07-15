// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

use serde::Serialize;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::sync::{Mutex, OnceLock};

static LOG_FILE: OnceLock<Mutex<Option<File>>> = OnceLock::new();

#[derive(Serialize)]
pub struct Entry<'a> {
    pub timestamp: String,
    pub level: &'a str,       // "info" | "warn" | "fatal"
    pub component: &'a str,
    pub message: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pid: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub event_type: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub action: Option<&'a str>,
}

#[allow(clippy::manual_c_str_literals)] // c"" literals require Rust 1.77; MSRV is 1.75
pub fn get_timestamp() -> String {
    unsafe {
        let mut raw_time: libc::time_t = 0;
        libc::time(&mut raw_time);
        let mut tm = std::mem::zeroed::<libc::tm>();
        libc::gmtime_r(&raw_time, &mut tm);
        let mut buf = [0u8; 64];
        let len = libc::strftime(
            buf.as_mut_ptr() as *mut libc::c_char,
            buf.len(),
            b"%Y-%m-%dT%H:%M:%SZ\0".as_ptr() as *const libc::c_char,
            &tm,
        );
        if len > 0 {
            if let Ok(s) = std::str::from_utf8(&buf[..len]) {
                return s.to_string();
            }
        }
    }
    // Fallback if libc time formatting fails
    if let Ok(duration) = std::time::SystemTime::now().duration_since(std::time::SystemTime::UNIX_EPOCH) {
        format!("{}s", duration.as_secs())
    } else {
        "0s".to_string()
    }
}

pub fn set_file_output(path: &std::path::Path) -> std::io::Result<()> {
    let file = OpenOptions::new()
        .create(true)
        .write(true)
        .append(true)
        .open(path)?;
    let mutex = LOG_FILE.get_or_init(|| Mutex::new(None));
    let mut guard = mutex.lock().unwrap();
    *guard = Some(file);
    Ok(())
}

pub fn log(entry: Entry) {
    let json_str = match serde_json::to_string(&entry) {
        Ok(json) => json,
        Err(_) => {
            // Fallback that never panics
            format!(
                "{{\"timestamp\":\"{}\",\"level\":\"{}\",\"component\":\"{}\",\"message\":\"{}\"}}",
                entry.timestamp, entry.level, entry.component, entry.message
            )
        }
    };

    println!("{}", json_str);

    if let Some(mutex) = LOG_FILE.get() {
        if let Ok(mut guard) = mutex.lock() {
            if let Some(file) = guard.as_mut() {
                let _ = writeln!(file, "{}", json_str);
            }
        }
    }
}

pub fn info(component: &str, message: &str) {
    log(Entry {
        timestamp: get_timestamp(),
        level: "info",
        component,
        message,
        pid: None,
        event_type: None,
        target: None,
        action: None,
    });
}

pub fn fatal(component: &str, message: &str) {
    log(Entry {
        timestamp: get_timestamp(),
        level: "fatal",
        component,
        message,
        pid: None,
        event_type: None,
        target: None,
        action: None,
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_serialize_log_entry() {
        let entry = Entry {
            timestamp: "2026-07-05T14:49:30Z".to_string(),
            level: "info",
            component: "test",
            message: "test message",
            pid: Some(1234),
            event_type: Some("Read"),
            target: Some("/path/to/file"),
            action: Some("Allow"),
        };
        let serialized = serde_json::to_string(&entry).unwrap();
        assert!(serialized.contains(r#""timestamp":"2026-07-05T14:49:30Z""#));
        assert!(serialized.contains(r#""level":"info""#));
        assert!(serialized.contains(r#""component":"test""#));
        assert!(serialized.contains(r#""message":"test message""#));
        assert!(serialized.contains(r#""pid":1234"#));
        assert!(serialized.contains(r#""event_type":"Read""#));
        assert!(serialized.contains(r#""target":"/path/to/file""#));
        assert!(serialized.contains(r#""action":"Allow""#));
    }

    #[test]
    fn test_omit_none_fields() {
        let entry = Entry {
            timestamp: "2026-07-05T14:49:30Z".to_string(),
            level: "info",
            component: "test",
            message: "test message",
            pid: None,
            event_type: None,
            target: None,
            action: None,
        };
        let serialized = serde_json::to_string(&entry).unwrap();
        assert!(!serialized.contains(r#""pid""#));
        assert!(!serialized.contains(r#""event_type""#));
        assert!(!serialized.contains(r#""target""#));
        assert!(!serialized.contains(r#""action""#));
    }

    #[test]
    fn test_get_timestamp_runs_without_panic() {
        let ts = get_timestamp();
        assert!(!ts.is_empty());
    }
}
