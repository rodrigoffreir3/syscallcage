// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;
use std::os::unix::io::AsRawFd;

use crate::enforcer::Event;
use crate::logging;

use aya::maps::RingBuf;
use aya::programs::{KProbe, TracePoint, Lsm};
use thiserror::Error;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct BpfSyscallRule {
    pub pattern: [u8; 128],
    pub kill_on_deny: u32,
}
unsafe impl aya::Pod for BpfSyscallRule {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnforcementMode {
    Sync,
    Reactive,
}

fn bpf_lsm_available_impl(lsm_path: &str) -> bool {
    std::fs::read_to_string(lsm_path)
        .map(|content| content.split(',').any(|lsm| lsm.trim() == "bpf"))
        .unwrap_or(false)
}

pub fn bpf_lsm_available() -> bool {
    bpf_lsm_available_impl("/sys/kernel/security/lsm")
}

pub fn detect_enforcement_mode() -> EnforcementMode {
    if bpf_lsm_available() {
        EnforcementMode::Sync
    } else {
        EnforcementMode::Reactive
    }
}

const EVENT_TYPE_READ: u32 = 1;
const EVENT_TYPE_EXEC: u32 = 3;
const EVENT_TYPE_NETWORK: u32 = 4;

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExitReason {
    None = 0,
    UserRequested = 1,
    TargetDied = 2,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct BpfEvent {
    pub pid: u32,
    pub event_type: u32,
    pub resolved: u8,
    pub target: [u8; 256],
}

// Safety: BpfEvent contains plain old data types (u32, u8, and arrays of u8),
// which has a stable C layout and no references, making it safe to copy.
unsafe impl aya::Pod for BpfEvent {}

#[derive(Debug, Error)]
pub enum MonitorError {
    #[error("bpf erro: {0}")]
    Bpf(#[from] aya::EbpfError),
    #[error("programa erro: {0}")]
    Program(#[from] aya::programs::ProgramError),
    #[error("map erro: {0}")]
    Map(#[from] aya::maps::MapError),
    #[error("io erro: {0}")]
    IO(#[from] std::io::Error),
    #[error("PID {0} não existe")]
    PidDoesNotExist(u32),
    #[error("criação de link falhou")]
    LinkCreationFailed,
}

pub struct Monitor {
    target_pid: u32,
    exit_reason: Arc<AtomicU8>,
    closed: Arc<AtomicBool>,
    bpf: Mutex<aya::Ebpf>,
    ip_to_domain: Mutex<aya::maps::HashMap<aya::maps::MapData, u32, [u8; 256]>>,
    local_dns_cache: Mutex<std::collections::HashMap<u32, String>>,
    _links: Vec<Box<dyn std::any::Any + Send + Sync>>, // Storing links to keep them alive
    handler: Arc<dyn Fn(Event) + Send + Sync + 'static>,
}

fn process_exists(pid: u32) -> bool {
    unsafe { libc::kill(pid as libc::pid_t, 0) == 0 }
}

/// Parseia QNAME e extrai todas as respostas do tipo A (IPv4) de um payload DNS raw de 256 bytes.
/// Retorna o QNAME (ex: "google.com") e a lista de IPs IPv4 em formato u32 big-endian.
fn parse_dns_answers(wire: &[u8]) -> Option<(String, Vec<u32>)> {
    if wire.len() < 12 { return None; }
    
    // ancount (Answers count) nos bytes 6 e 7
    let ancount = ((wire[6] as u16) << 8) | (wire[7] as u16);
    if ancount == 0 { return None; }

    // Parse do QNAME na Question Section
    let first_label_len = wire[12] as usize;
    if first_label_len == 0 || first_label_len > 63 { return None; }
    let mut pos = 12;
    let mut qname = String::with_capacity(64);
    let mut first = true;
    loop {
        if pos >= wire.len() { return None; }
        let len = wire[pos] as usize;
        if len == 0 { break; }
        if len > 63 { return None; }
        if !first { qname.push('.'); }
        first = false;
        pos += 1;
        if pos + len > wire.len() { return None; }
        qname.push_str(std::str::from_utf8(&wire[pos..pos + len]).ok()?);
        pos += len;
    }
    
    if qname.is_empty() { return None; }
    
    // Pula o terminador nulo da Question Section
    pos += 1;
    // Pula QTYPE (2 bytes) e QCLASS (2 bytes)
    pos += 4;

    let mut ips = Vec::new();

    // Answer Section parsing
    for _ in 0..ancount {
        if pos >= wire.len() { break; }
        
        // Pula/Parseia NAME do registro
        let b = wire[pos];
        if (b & 0xC0) == 0xC0 {
            // Compressão: ocupa 2 bytes
            pos += 2;
        } else {
            // Sem compressão: sequência de labels terminada em 0
            loop {
                if pos >= wire.len() { return None; }
                let len = wire[pos] as usize;
                if len == 0 {
                    pos += 1;
                    break;
                }
                if len > 63 { return None; }
                pos += 1 + len;
            }
        }

        // Verifica se temos espaço para TYPE (2), CLASS (2), TTL (4), RDLENGTH (2)
        if pos + 10 > wire.len() { break; }
        
        let rtype = ((wire[pos] as u16) << 8) | (wire[pos + 1] as u16);
        pos += 2; // TYPE
        pos += 2; // CLASS
        pos += 4; // TTL
        
        let rdlength = (((wire[pos] as u16) << 8) | (wire[pos + 1] as u16)) as usize;
        pos += 2; // RDLENGTH

        if pos + rdlength > wire.len() { break; }

        // Se TYPE for A (0x0001) e RDLENGTH for 4, extrai o IP IPv4
        if rtype == 1 && rdlength == 4 {
            let ip_bytes = &wire[pos..pos + 4];
            let ip_be = ((ip_bytes[0] as u32) << 24)
                | ((ip_bytes[1] as u32) << 16)
                | ((ip_bytes[2] as u32) << 8)
                | (ip_bytes[3] as u32);
            ips.push(ip_be);
        }

        pos += rdlength;
    }

    Some((qname, ips))
}

fn parse_tracepoint_offset(format_content: &str, field_name: &str) -> Option<u32> {
    for line in format_content.lines() {
        if line.contains(field_name) && line.contains("offset:") {
            if let Some(pos) = line.find("offset:") {
                let start = pos + "offset:".len();
                let end = line[start..].find(';').unwrap_or(line[start..].len()) + start;
                if let Ok(offset) = line[start..end].trim().parse::<u32>() {
                    return Some(offset);
                }
            }
        }
    }
    None
}

impl Monitor {
    pub fn new(
        target_pid: u32,
        policy: &crate::policy::Policy,
        handler: impl Fn(Event) + Send + Sync + 'static,
    ) -> Result<Self, MonitorError> {
        if !process_exists(target_pid) {
            return Err(MonitorError::PidDoesNotExist(target_pid));
        }

        // Remove memory lock limit (essential for loading BPF programs)
        unsafe {
            let rlim = libc::rlimit {
                rlim_cur: libc::RLIM_INFINITY,
                rlim_max: libc::RLIM_INFINITY,
            };
            if libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) != 0 {
                logging::info("monitor", "falha ao remover limite memlock (pode ser normal em kernel novo)");
            }
        }

        // Find the eBPF object at runtime.
        let ebpf_obj_path = locate_ebpf_binary().map_err(|e| {
            MonitorError::IO(std::io::Error::new(
                e.kind(),
                format!(
                    "{}. Defina SYSCALLCAGE_EBPF_PATH ou compile com: cargo +nightly build --bin syscallcage-ebpf --target bpfel-unknown-none -Z build-std=core --release",
                    e
                )
            ))
        })?;

        let bpf_bytes = std::fs::read(&ebpf_obj_path).map_err(|e| {
            MonitorError::IO(std::io::Error::new(
                e.kind(),
                format!("falha ao ler {:?}: {}", ebpf_obj_path, e),
            ))
        })?;
        let mut bpf = aya::Ebpf::load(&bpf_bytes)?;

        // Register target PID in MONITORED_PIDS map
        let monitored_pids_map = bpf.map_mut("MONITORED_PIDS").ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::NotFound, "map MONITORED_PIDS não encontrado")
        })?;
        let mut monitored_pids = aya::maps::HashMap::try_from(monitored_pids_map)?;
        monitored_pids.insert(target_pid, 1u8, 0)?;

        // Configura offsets dinâmicos para o tracepoint sched_process_fork em runtime
        let offsets_map = bpf.map_mut("OFFSETS").ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::NotFound, "map OFFSETS não encontrado")
        })?;
        let mut offsets = aya::maps::HashMap::try_from(offsets_map)?;
        
        let mut parent_offset = 12u32;
        let mut child_offset = 20u32;
        
        let format_paths = [
            "/sys/kernel/debug/tracing/events/sched/sched_process_fork/format",
            "/sys/kernel/tracing/events/sched/sched_process_fork/format",
        ];
        let mut format_data = None;
        for path in &format_paths {
            if let Ok(data) = std::fs::read_to_string(path) {
                format_data = Some(data);
                break;
            }
        }

        if let Some(data) = format_data {
            if let Some(p_off) = parse_tracepoint_offset(&data, "parent_pid") {
                parent_offset = p_off;
            }
            if let Some(c_off) = parse_tracepoint_offset(&data, "child_pid") {
                child_offset = c_off;
            }
            logging::info("monitor", &format!("Offsets detectados em runtime para sched_process_fork: parent_pid={}, child_pid={}", parent_offset, child_offset));
        } else {
            logging::info("monitor", "falha ao ler formato do tracepoint sched_process_fork, usando fallbacks padrão (12/20)");
        }
        
        offsets.insert(1u32, parent_offset, 0)?;
        offsets.insert(2u32, child_offset, 0)?;

        let (f_mode_off, f_path_off, bprm_file_off) = resolve_btf_offsets();
        offsets.insert(3u32, f_mode_off, 0)?;
        offsets.insert(4u32, f_path_off, 0)?;
        offsets.insert(5u32, bprm_file_off, 0)?;
        logging::info("monitor", &format!(
            "Offsets dinâmicos estruturais resolvidos: f_mode={}, f_path={}, bprm_file={}",
            f_mode_off, f_path_off, bprm_file_off
        ));

        let ip_to_domain_map = bpf.take_map("IP_TO_DOMAIN").ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::NotFound, "map IP_TO_DOMAIN não encontrado")
        })?;
        let ip_to_domain = Mutex::new(aya::maps::HashMap::try_from(ip_to_domain_map)?);

        let mut _links: Vec<Box<dyn std::any::Any + Send + Sync>> = Vec::new();

        // ── Attach do conjunto de programas baseado no EnforcementMode ────────────────
        let mut lsm_attached = false;
        let mode = detect_enforcement_mode();
        if mode == EnforcementMode::Sync {
            logging::info("monitor", "Tentando inicializar modo síncrono (BPF LSM)...");
            match crate::policy_sync_compiler::try_compile_for_sync(policy) {
                Ok(sync_policy) => {
                    let mut attach_ok = true;
                    let btf = match aya::Btf::from_sys_fs() {
                        Ok(b) => Some(b),
                        Err(e) => {
                            logging::info("monitor", &format!("falha ao carregar BTF do kernel: {:?}", e));
                            attach_ok = false;
                            None
                        }
                    };

                    if attach_ok {
                        if let Some(prog) = bpf.program_mut("lsm_file_open") {
                            let lsm: &mut Lsm = match prog.try_into() {
                                Ok(l) => l,
                                Err(e) => {
                                    logging::info("monitor", &format!("falha ao carregar lsm_file_open: {:?}", e));
                                    attach_ok = false;
                                    return Err(MonitorError::Program(e));
                                }
                            };
                            if attach_ok {
                                if let Some(ref btf_obj) = btf {
                                    lsm.load("file_open", btf_obj)?;
                                    let link = lsm.attach()?;
                                    _links.push(Box::new(link));
                                }
                            }
                        } else {
                            logging::info("monitor", "LSM lsm_file_open não encontrado");
                            attach_ok = false;
                        }
                    }

                    if attach_ok {
                        if let Some(prog) = bpf.program_mut("lsm_exec_check") {
                            let lsm: &mut Lsm = match prog.try_into() {
                                Ok(l) => l,
                                Err(e) => {
                                    logging::info("monitor", &format!("falha ao carregar lsm_exec_check: {:?}", e));
                                    attach_ok = false;
                                    return Err(MonitorError::Program(e));
                                }
                            };
                            if attach_ok {
                                if let Some(ref btf_obj) = btf {
                                    lsm.load("bprm_check_security", btf_obj)?;
                                    let link = lsm.attach()?;
                                    _links.push(Box::new(link));
                                }
                            }
                        } else {
                            logging::info("monitor", "LSM lsm_exec_check não encontrado");
                            attach_ok = false;
                        }
                    }


                    if attach_ok {
                        // Popula os mapas no eBPF
                        if let Some(map_data) = bpf.map_mut("ENFORCE_MODE") {
                            let mut map = aya::maps::HashMap::<_, u32, u32>::try_from(map_data)?;
                            let mode_val = if policy.mode() == crate::policy::Mode::Enforce { 1 } else { 0 };
                            map.insert(0u32, mode_val, 0)?;
                        }
                        if let Some(map_data) = bpf.map_mut("ALLOW_READ_PREFIXES") {
                            let mut map = aya::maps::HashMap::<_, u32, [u8; 128]>::try_from(map_data)?;
                            for (i, prefix) in sync_policy.allow_read_prefixes.iter().enumerate() {
                                map.insert(i as u32, *prefix, 0)?;
                            }
                        }
                        if let Some(map_data) = bpf.map_mut("ALLOW_WRITE_PREFIXES") {
                            let mut map = aya::maps::HashMap::<_, u32, [u8; 128]>::try_from(map_data)?;
                            for (i, prefix) in sync_policy.allow_write_prefixes.iter().enumerate() {
                                map.insert(i as u32, *prefix, 0)?;
                            }
                        }
                        if let Some(map_data) = bpf.map_mut("DENY_ALWAYS_PREFIXES") {
                            let mut map = aya::maps::HashMap::<_, u32, [u8; 128]>::try_from(map_data)?;
                            for (i, prefix) in sync_policy.deny_always_prefixes.iter().enumerate() {
                                map.insert(i as u32, *prefix, 0)?;
                            }
                        }
                        if let Some(map_data) = bpf.map_mut("DENY_SYSCALLS_RULES") {
                            let mut map = aya::maps::HashMap::<_, u32, BpfSyscallRule>::try_from(map_data)?;
                            for (i, (pattern, kill)) in sync_policy.deny_syscalls_rules.iter().enumerate() {
                                let rule = BpfSyscallRule {
                                    pattern: *pattern,
                                    kill_on_deny: if *kill { 1 } else { 0 },
                                };
                                map.insert(i as u32, rule, 0)?;
                            }
                        }
                        lsm_attached = true;
                        logging::info("monitor", "Modo de enforcement síncrono (BPF LSM) ativado com sucesso.");
                    } else {
                        logging::info("monitor", "Falha ao atrelar hooks LSM. Caindo para modo reativo.");
                    }
                }
                Err(e) => {
                    logging::info("monitor", &format!("Não foi possível carregar política no modo síncrono (caindo para modo reativo): {}", e));
                }
            }
        } else {
            logging::info("monitor", "Modo síncrono (BPF LSM) indisponível. Ativando modo reativo.");
        }

        // ── Programas comuns a ambos os modos (ciclo de vida e rede) ──────────────────

        // Attach tracepoint: sched_process_fork
        if let Some(prog) = bpf.program_mut("handle_fork") {
            let tp: &mut TracePoint = prog.try_into()?;
            tp.load()?;
            let link = tp.attach("sched", "sched_process_fork")?;
            _links.push(Box::new(link));
        }

        // Attach tracepoint: sched_process_exit
        if let Some(prog) = bpf.program_mut("handle_exit") {
            let tp: &mut TracePoint = prog.try_into()?;
            tp.load()?;
            let link = tp.attach("sched", "sched_process_exit")?;
            _links.push(Box::new(link));
        }

        // Attach tracepoint: sys_enter_connect (rede)
        if let Some(prog) = bpf.program_mut("handle_connect") {
            let tp: &mut TracePoint = prog.try_into()?;
            tp.load()?;
            let link = tp.attach("syscalls", "sys_enter_connect")?;
            _links.push(Box::new(link));
        }

        // Attach tracepoint: sys_enter_sendto (rede)
        if let Some(prog) = bpf.program_mut("handle_sendto") {
            let tp: &mut TracePoint = prog.try_into()?;
            tp.load()?;
            let link = tp.attach("syscalls", "sys_enter_sendto")?;
            _links.push(Box::new(link));
        }

        // Attach tracepoint: sys_enter_recvfrom (rede)
        if let Some(prog) = bpf.program_mut("handle_enter_recvfrom") {
            let tp: &mut TracePoint = prog.try_into()?;
            tp.load()?;
            let link = tp.attach("syscalls", "sys_enter_recvfrom")?;
            _links.push(Box::new(link));
        }

        // Attach tracepoint: sys_exit_recvfrom (rede)
        if let Some(prog) = bpf.program_mut("handle_exit_recvfrom") {
            let tp: &mut TracePoint = prog.try_into()?;
            tp.load()?;
            let link = tp.attach("syscalls", "sys_exit_recvfrom")?;
            _links.push(Box::new(link));
        }

        // ── Programas exclusivos do modo reativo (filesystem e execve) ───────────────
        if !lsm_attached {
            // Attach kprobe: handle_open (atrelado a ambos do_sys_open e do_sys_openat2)
            if let Some(prog) = bpf.program_mut("handle_open") {
                let kprobe: &mut KProbe = prog.try_into()?;
                kprobe.load()?;
                match kprobe.attach("do_sys_open", 0) {
                    Ok(link) => _links.push(Box::new(link)),
                    Err(e) => {
                        logging::info("monitor", &format!("falha ao atrelar kprobe do_sys_open: {:?}", e));
                    }
                }
                match kprobe.attach("do_sys_openat2", 0) {
                    Ok(link) => _links.push(Box::new(link)),
                    Err(e) => {
                        logging::info("monitor", &format!("falha ao atrelar kprobe do_sys_openat2: {:?}", e));
                    }
                }
            }

            // Attach tracepoint: sys_enter_execve
            if let Some(prog) = bpf.program_mut("handle_execve") {
                let tp: &mut TracePoint = prog.try_into()?;
                tp.load()?;
                let link = tp.attach("syscalls", "sys_enter_execve")?;
                _links.push(Box::new(link));
            }

            // Attach tracepoint: sys_enter_ptrace
            if let Some(prog) = bpf.program_mut("handle_ptrace") {
                let tp: &mut TracePoint = prog.try_into()?;
                tp.load()?;
                let link = tp.attach("syscalls", "sys_enter_ptrace")?;
                _links.push(Box::new(link));
            }
        }

        Ok(Self {
            target_pid,
            exit_reason: Arc::new(AtomicU8::new(ExitReason::None as u8)),
            closed: Arc::new(AtomicBool::new(false)),
            bpf: Mutex::new(bpf),
            ip_to_domain,
            local_dns_cache: Mutex::new(std::collections::HashMap::new()),
            _links,
            handler: Arc::new(handler),
        })
    }

    pub fn start(&self) -> Result<(), MonitorError> {
        let exit_reason = self.exit_reason.clone();
        let target_pid = self.target_pid;
        let closed = self.closed.clone();

        // Spawn thread checking target liveness
        std::thread::spawn(move || {
            while !closed.load(Ordering::SeqCst) {
                std::thread::sleep(Duration::from_secs(2));
                if !process_exists(target_pid) {
                    logging::info(
                        "monitor",
                        &format!("processo monitorado {} terminou naturalmente, encerrando", target_pid)
                    );
                    let _ = exit_reason.compare_exchange(
                        ExitReason::None as u8,
                        ExitReason::TargetDied as u8,
                        Ordering::SeqCst,
                        Ordering::SeqCst,
                    );
                    closed.store(true, Ordering::SeqCst);
                    break;
                }
            }
        });

        // Event loop locks Ebpf only for initialization
        let events_map = {
            let mut bpf_guard = self.bpf.lock().unwrap();
            bpf_guard.take_map("EVENTS").ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::NotFound, "map EVENTS não encontrado")
            })?
        };
        let mut ring_buf = RingBuf::try_from(events_map)?;

        let fd = ring_buf.as_raw_fd();
        let mut poll_fd = libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        };

        while !self.closed.load(Ordering::SeqCst) {
            let ret = unsafe { libc::poll(&mut poll_fd, 1, 500) };
            if ret < 0 {
                let err = std::io::Error::last_os_error();
                if err.kind() == std::io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(MonitorError::IO(err));
            }

            if ret > 0 && (poll_fd.revents & libc::POLLIN) != 0 {
                while let Some(item) = ring_buf.next() {
                    if item.len() < std::mem::size_of::<BpfEvent>() {
                        continue;
                    }
                    let bpf_event = unsafe { &*(item.as_ptr() as *const BpfEvent) };

                    let event_type = match bpf_event.event_type {
                        EVENT_TYPE_READ => crate::enforcer::EventType::Read,
                        EVENT_TYPE_EXEC => crate::enforcer::EventType::Syscall,
                        EVENT_TYPE_NETWORK => crate::enforcer::EventType::Network,
                        _ => continue, // Ignore unknown event types
                    };

                    let mut resolved = bpf_event.resolved == 1 || bpf_event.resolved == 2;

                    let target_str = if bpf_event.event_type == EVENT_TYPE_NETWORK && bpf_event.resolved == 0 && bpf_event.target[0] == 0xAA {
                        // IP bruto codificado com tag 0xAA pelo handle_connect.
                        // Resolve via cache local em userspace para evitar race conditions do eBPF
                        let ip_val = ((bpf_event.target[1] as u32) << 24)
                            | ((bpf_event.target[2] as u32) << 16)
                            | ((bpf_event.target[3] as u32) << 8)
                            | (bpf_event.target[4] as u32);
                        
                        let local_cache = self.local_dns_cache.lock().unwrap();
                        if let Some(domain) = local_cache.get(&ip_val) {
                            resolved = true;
                            domain.clone()
                        } else {
                            format!(
                                "{}.{}.{}.{}",
                                bpf_event.target[1],
                                bpf_event.target[2],
                                bpf_event.target[3],
                                bpf_event.target[4]
                            )
                        }
                    } else if bpf_event.event_type == EVENT_TYPE_NETWORK && bpf_event.resolved == 1 {
                        // Parseia QNAME e todas as respostas A do DNS
                        let (dns_name, ips) = if let Some((name, ips)) = parse_dns_answers(&bpf_event.target) {
                            (name, ips)
                        } else {
                            ("<dns-parse-error>".to_string(), Vec::new())
                        };

                        logging::info("monitor", &format!("DNS resolvido: {} -> {:?}", dns_name, ips));

                        // Se encontrou IPs associados, grava-os no mapa IP_TO_DOMAIN do eBPF e local_dns_cache
                        if !ips.is_empty() {
                            let mut local_cache = self.local_dns_cache.lock().unwrap();
                            let mut ip_to_domain_map = self.ip_to_domain.lock().unwrap();
                            let mut domain_buf = [0u8; 256];
                            let name_bytes = dns_name.as_bytes();
                            let copy_len = std::cmp::min(name_bytes.len(), 255);
                            domain_buf[..copy_len].copy_from_slice(&name_bytes[..copy_len]);
                            for ip in ips {
                                local_cache.insert(ip, dns_name.clone());
                                if let Err(e) = ip_to_domain_map.insert(ip, domain_buf, 0) {
                                    logging::info("monitor", &format!("falha ao inserir IP no mapa IP_TO_DOMAIN: {:?}", e));
                                }
                            }
                        }

                        dns_name
                    } else {
                        let null_pos = bpf_event.target.iter().position(|&c| c == 0).unwrap_or(256);
                        let decoded = String::from_utf8_lossy(&bpf_event.target[..null_pos]);
                        if bpf_event.event_type == EVENT_TYPE_EXEC {
                            format!("execve:{}", decoded)
                        } else {
                            decoded.into_owned()
                        }
                    };

                    let event = Event {
                        pid: bpf_event.pid,
                        event_type,
                        target: target_str,
                        resolved,
                    };

                    (self.handler)(event);
                }
            }
        }

        Ok(())
    }

    pub fn exited_because_target_died(&self) -> bool {
        self.exit_reason.load(Ordering::SeqCst) == ExitReason::TargetDied as u8
    }

    pub fn close(&self) {
        let _ = self.exit_reason.compare_exchange(
            ExitReason::None as u8,
            ExitReason::UserRequested as u8,
            Ordering::SeqCst,
            Ordering::SeqCst,
        );
        self.closed.store(true, Ordering::SeqCst);
    }
}

impl Drop for Monitor {
    fn drop(&mut self) {
        self.closed.store(true, Ordering::SeqCst);
        // Links inside self._links are Boxed and will be dropped naturally,
        // which detaches all kprobes/tracepoints in Aya automatically!
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_process_exists_self() {
        let own_pid = std::process::id();
        assert!(process_exists(own_pid), "o próprio processo deve existir");
    }

    #[test]
    fn test_process_exists_nonexistent() {
        // PID 0x7FFFFFFF é absurdamente alto e não existe em nenhum sistema normal
        assert!(!process_exists(0x7FFF_FFFF), "PID absurdo não deve existir");
    }

    #[test]
    fn test_monitor_new_rejects_nonexistent_pid() {
        let yaml = "mode: enforce\nfilesystem:\n  allow_read:\n    - \"**\"";
        let policy = crate::policy::Policy::from_yaml(yaml).unwrap();
        let result = Monitor::new(0x7FFF_FFFF, &policy, |_| {});
        assert!(
            matches!(result, Err(MonitorError::PidDoesNotExist(_))),
            "deve retornar PidDoesNotExist antes de tentar carregar eBPF"
        );
    }

    #[test]
    fn test_parse_dns_answers_valid() {
        // Header com ancount = 1
        let mut wire = vec![0u8; 12];
        wire[7] = 1; // ancount = 1
        
        // Question: "google.com" -> \x06google\x03com\x00, QTYPE=1, QCLASS=1
        wire.extend_from_slice(b"\x06google\x03com\x00");
        wire.extend_from_slice(&[0, 1, 0, 1]); // QTYPE, QCLASS
        
        // Answer: NAME (pointer to offset 12 -> 0xc00c), TYPE=1 (A), CLASS=1, TTL=60, RDLENGTH=4, RDATA=1.2.3.4
        wire.extend_from_slice(&[0xc0, 12]);
        wire.extend_from_slice(&[0, 1, 0, 1]); // TYPE, CLASS
        wire.extend_from_slice(&[0, 0, 0, 60]); // TTL
        wire.extend_from_slice(&[0, 4]); // RDLENGTH
        wire.extend_from_slice(&[1, 2, 3, 4]); // RDATA

        let res = parse_dns_answers(&wire);
        assert!(res.is_some());
        let (name, ips) = res.unwrap();
        assert_eq!(name, "google.com");
        assert_eq!(ips, vec![0x01020304]);
    }

    #[test]
    fn test_bpf_lsm_available_mocked() {
        use std::io::Write;
        
        let mut temp_file = std::env::temp_dir().join("mock_lsm");
        
        // Caso 1: suportado
        {
            let mut f = std::fs::File::create(&temp_file).unwrap();
            f.write_all(b"lockdown,capability,bpf,landlock").unwrap();
        }
        assert!(bpf_lsm_available_impl(temp_file.to_str().unwrap()));
        
        // Caso 2: não suportado
        {
            let mut f = std::fs::File::create(&temp_file).unwrap();
            f.write_all(b"lockdown,capability,landlock").unwrap();
        }
        assert!(!bpf_lsm_available_impl(temp_file.to_str().unwrap()));
        
        let _ = std::fs::remove_file(temp_file);
    }
}

fn resolve_btf_offsets() -> (u32, u32, u32) {
    // Fallbacks padrão seguros (caso a resolução via bpftool falhe)
    let mut f_mode_offset = 4u32;
    let mut f_path_offset = 64u32;
    let mut bprm_file_offset = 64u32;

    let output = std::process::Command::new("bpftool")
        .args(&["btf", "dump", "file", "/sys/kernel/btf/vmlinux", "format", "raw"])
        .output();

    if let Ok(out) = output {
        if out.status.success() {
            let stdout = String::from_utf8_lossy(&out.stdout);
            let mut in_file_struct = false;
            let mut in_bprm_struct = false;

            for line in stdout.lines() {
                let trimmed = line.trim();
                if trimmed.starts_with("STRUCT 'file'") {
                    in_file_struct = true;
                    in_bprm_struct = false;
                    continue;
                } else if trimmed.starts_with("STRUCT 'linux_binprm'") {
                    in_file_struct = false;
                    in_bprm_struct = true;
                    continue;
                } else if trimmed.starts_with("STRUCT") || (trimmed.starts_with('[') && trimmed.contains("STRUCT")) {
                    in_file_struct = false;
                    in_bprm_struct = false;
                    continue;
                }

                if in_file_struct {
                    if trimmed.contains("'f_mode'") {
                        if let Some(offset) = extract_bits_offset(trimmed) {
                            f_mode_offset = offset / 8;
                        }
                    } else if trimmed.contains("'f_path'") {
                        if let Some(offset) = extract_bits_offset(trimmed) {
                            f_path_offset = offset / 8;
                        }
                    }
                } else if in_bprm_struct {
                    if trimmed.contains("'file'") {
                        if let Some(offset) = extract_bits_offset(trimmed) {
                            bprm_file_offset = offset / 8;
                        }
                    }
                }
            }
        }
    }

    (f_mode_offset, f_path_offset, bprm_file_offset)
}

fn extract_bits_offset(line: &str) -> Option<u32> {
    if let Some(pos) = line.find("bits_offset=") {
        let start = pos + "bits_offset=".len();
        let rest = &line[start..];
        let end = rest.find(' ').unwrap_or(rest.len());
        rest[..end].parse::<u32>().ok()
    } else {
        None
    }
}

pub fn locate_ebpf_binary() -> Result<std::path::PathBuf, std::io::Error> {
    if let Ok(env_path) = std::env::var("SYSCALLCAGE_EBPF_PATH").or_else(|_| std::env::var("AGENT_CAGE_EBPF_PATH")) {
        let p = std::path::PathBuf::from(env_path);
        if p.exists() {
            return Ok(p);
        }
    }

    let exe = std::env::current_exe().unwrap_or_default();
    let exe_dir = exe.parent().unwrap_or(std::path::Path::new("."));

    // Candidate 1: sibling of binary (production / installed)
    let sibling = exe_dir.join("syscallcage-ebpf");
    // Candidate 2: binary in project root, eBPF in target/bpfel-unknown-none/release/
    let root_release = exe_dir.join("target/bpfel-unknown-none/release/syscallcage-ebpf");
    // Candidate 3: binary at target/release/syscallcage, eBPF at target/bpfel-unknown-none/release/
    let cargo_release = exe_dir
        .parent().unwrap_or(exe_dir)
        .join("bpfel-unknown-none/release/syscallcage-ebpf");
    // Candidate 4: same but debug (fallback)
    let root_debug = exe_dir.join("target/bpfel-unknown-none/debug/syscallcage-ebpf");
    let cargo_debug = exe_dir
        .parent().unwrap_or(exe_dir)
        .join("bpfel-unknown-none/debug/syscallcage-ebpf");

    let candidates = [sibling, root_release, cargo_release, root_debug, cargo_debug];
    for p in candidates {
        if p.exists() {
            return Ok(p);
        }
    }

    Err(std::io::Error::new(
        std::io::ErrorKind::NotFound,
        "syscallcage-ebpf object não encontrado"
    ))
}
