// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#![cfg_attr(target_arch = "bpf", no_std)]
#![cfg_attr(target_arch = "bpf", no_main)]

#[cfg(target_arch = "bpf")]
use aya_ebpf::{
    macros::{kprobe, lsm, map, tracepoint},
    maps::{HashMap, LruHashMap, PerCpuArray, RingBuf},
    programs::{LsmContext, ProbeContext, TracePointContext},
    helpers::{
        bpf_get_current_pid_tgid, bpf_probe_read_user, bpf_probe_read_user_buf,
        bpf_probe_read_user_str_bytes, bpf_d_path, bpf_send_signal,
    },
};

#[cfg(target_arch = "bpf")]
#[repr(C)]
pub struct path {
    pub mnt: *mut core::ffi::c_void,
    pub dentry: *mut core::ffi::c_void,
}

#[cfg(target_arch = "bpf")]
#[repr(C)]
pub struct file {
    pub _padding: [u8; 64],
    pub f_path: path,
}

#[cfg(target_arch = "bpf")]
#[repr(C)]
pub struct linux_binprm {
    pub _padding: [u8; 64],
    pub file: *mut file,
}

#[cfg(target_arch = "bpf")]
const EVENT_TYPE_READ: u32 = 1;
#[cfg(target_arch = "bpf")]
const EVENT_TYPE_WRITE: u32 = 2;
#[cfg(target_arch = "bpf")]
const EVENT_TYPE_EXEC: u32 = 3;
#[cfg(target_arch = "bpf")]
const EVENT_TYPE_NETWORK: u32 = 4;
#[cfg(target_arch = "bpf")]
const EVENT_TYPE_SYSCALL: u32 = 5;

#[cfg(target_arch = "bpf")]
#[repr(C)]
#[derive(Clone, Copy)]
pub struct BpfEvent {
    pub pid: u32,
    pub event_type: u32,
    pub resolved: u8,
    pub target: [u8; 256],
}

// ── Mapas ────────────────────────────────────────────────────────────────────

/// Ring buffer de eventos para userspace consumir
#[cfg(target_arch = "bpf")]
#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(16_777_216, 0);

/// PIDs que estão sendo monitorados (pid → 1)
#[cfg(target_arch = "bpf")]
#[map]
static MONITORED_PIDS: LruHashMap<u32, u8> = LruHashMap::with_max_entries(10240, 0);

/// Queries DNS pendentes: tx_id → raw payload (256 bytes)
#[cfg(target_arch = "bpf")]
#[map]
static PENDING_DNS_QUERY: LruHashMap<u16, [u8; 256]> = LruHashMap::with_max_entries(1024, 0);

/// Ponteiros de buffer do recvfrom em andamento: pid_tgid → ptr
#[cfg(target_arch = "bpf")]
#[map]
static DNS_RECV_BUFF: LruHashMap<u64, u64> = LruHashMap::with_max_entries(1024, 0);

/// Mapeamento IP→domínio construído pelo userspace (não mais pelo eBPF)
#[cfg(target_arch = "bpf")]
#[map]
static IP_TO_DOMAIN: LruHashMap<u32, [u8; 256]> = LruHashMap::with_max_entries(4096, 0);

/// Scratch space por CPU para evitar escrita com offset variável na stack
/// (proibido pelo verifier BPF)
#[cfg(target_arch = "bpf")]
#[map]
static SCRATCH_DOMAIN: PerCpuArray<[u8; 512]> = PerCpuArray::with_max_entries(1, 0);

/// Scratch space para caminhos temporários resolvidos
#[cfg(target_arch = "bpf")]
#[map]
static SCRATCH_PATH: PerCpuArray<[u8; 256]> = PerCpuArray::with_max_entries(1, 0);

/// FDs de socket DNS: (pid << 32 | fd) → 1
#[cfg(target_arch = "bpf")]
#[map]
static DNS_FDS: LruHashMap<u64, u8> = LruHashMap::with_max_entries(1024, 0);

/// Offsets dinâmicos do tracepoint sched_process_fork em runtime (1 = parent_pid, 2 = child_pid)
#[cfg(target_arch = "bpf")]
#[map]
static OFFSETS: HashMap<u32, u32> = HashMap::with_max_entries(10, 0);

#[cfg(target_arch = "bpf")]
#[map]
static ALLOW_READ_PREFIXES: HashMap<u32, [u8; 128]> = HashMap::with_max_entries(16, 0);

#[cfg(target_arch = "bpf")]
#[map]
static ALLOW_WRITE_PREFIXES: HashMap<u32, [u8; 128]> = HashMap::with_max_entries(16, 0);

#[cfg(target_arch = "bpf")]
#[map]
static DENY_ALWAYS_PREFIXES: HashMap<u32, [u8; 128]> = HashMap::with_max_entries(16, 0);

#[cfg(target_arch = "bpf")]
#[repr(C)]
#[derive(Clone, Copy)]
pub struct SyscallRule {
    pub pattern: [u8; 128],
    pub kill_on_deny: u32,
}

#[cfg(target_arch = "bpf")]
#[map]
static DENY_SYSCALLS_RULES: HashMap<u32, SyscallRule> = HashMap::with_max_entries(16, 0);

#[cfg(target_arch = "bpf")]
#[map]
static ENFORCE_MODE: HashMap<u32, u32> = HashMap::with_max_entries(1, 0);


// ── Helpers ──────────────────────────────────────────────────────────────────

/// Verifica se o PID atual está sendo monitorado.
#[cfg(target_arch = "bpf")]
#[inline(always)]
#[link_section = ".text"]
fn is_monitored(pid: u32) -> bool {
    unsafe { MONITORED_PIDS.get(&pid) }.map(|v| *v == 1).unwrap_or(false)
}

/// Verifica se o enforcer está rodando em modo Enforce (1 = enforce, 0 = monitor).
/// Default para true (1) para garantir Zero Trust caso o mapa não esteja preenchido.
#[cfg(target_arch = "bpf")]
#[inline(always)]
#[link_section = ".text"]
fn is_enforce_mode() -> bool {
    unsafe { ENFORCE_MODE.get(&0) }.map(|v| *v == 1).unwrap_or(true)
}

/// Obtém o offset dinâmico de f_mode (struct file) ou seu fallback (4)
#[cfg(target_arch = "bpf")]
#[inline(always)]
#[link_section = ".text"]
fn get_f_mode_offset() -> u32 {
    unsafe { OFFSETS.get(&3) }.map(|v| *v).unwrap_or(4)
}

// f_path e linux_binprm.file não usam mais offset manual (OFFSETS 4/5): o
// acesso agora é via campo tipado (&raw mut (*ptr).campo), que preserva
// proveniência BTF exigida por bpf_d_path. Ver GT-13. O offset de f_mode
// (índice 3) continua via OFFSETS pois bpf_probe_read_kernel não exige tipo.

// ── Programas eBPF ───────────────────────────────────────────────────────────

/// Herda monitoramento para processos filhos (fork/clone) usando tracepoint estável com offsets dinâmicos.
/// Seção: "tracepoint/sched/sched_process_fork"
#[cfg(target_arch = "bpf")]
#[tracepoint(category = "sched", name = "sched_process_fork")]
pub fn handle_fork(ctx: TracePointContext) -> u32 {
    let parent_offset = unsafe { OFFSETS.get(&1) }.map(|v| *v).unwrap_or(12);
    let child_offset = unsafe { OFFSETS.get(&2) }.map(|v| *v).unwrap_or(20);

    let parent_pid: i32 = unsafe { ctx.read_at(parent_offset as usize) }.unwrap_or(0);
    let child_pid: i32 = unsafe { ctx.read_at(child_offset as usize) }.unwrap_or(0);

    if parent_pid > 0 && child_pid > 0 {
        if is_monitored(parent_pid as u32) {
            let _ = MONITORED_PIDS.insert(child_pid as u32, 1u8, 0);
        }
    }
    0
}

/// Remove PID do mapa quando processo encerra.
/// Seção: "tracepoint/sched/sched_process_exit"
#[cfg(target_arch = "bpf")]
#[tracepoint(category = "sched", name = "sched_process_exit")]
pub fn handle_exit(ctx: TracePointContext) -> u32 {
    let pid: i32 = unsafe { ctx.read_at(24) }.unwrap_or(0);
    let _ = MONITORED_PIDS.remove(pid as u32);
    0
}

/// Intercepta abertura de arquivo via open/openat2.
/// Seção: "kprobe/do_sys_open"
#[cfg(target_arch = "bpf")]
#[kprobe]
pub fn handle_open(ctx: ProbeContext) -> u32 {
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    if !is_monitored(pid) { return 0; }
    let filename_ptr: *const u8 = match ctx.arg(1) {
        Some(ptr) => ptr,
        None => return 0,
    };
    if let Some(mut entry) = EVENTS.reserve::<BpfEvent>(0) {
        let ev = entry.write(BpfEvent { pid, event_type: EVENT_TYPE_READ, resolved: 0, target: [0; 256] });
        let _ = unsafe { bpf_probe_read_user_str_bytes(filename_ptr, &mut ev.target) };
        entry.submit(0);
    }
    0
}

/// Intercepta execve para detectar execução de subprocessos.
/// Seção: "tracepoint/syscalls/sys_enter_execve"
#[cfg(target_arch = "bpf")]
#[tracepoint(category = "syscalls", name = "sys_enter_execve")]
pub fn handle_execve(ctx: TracePointContext) -> u32 {
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    if !is_monitored(pid) { return 0; }
    let filename_ptr: *const u8 = match unsafe { ctx.read_at(16) } {
        Ok(ptr) => ptr,
        Err(_) => return 0,
    };
    if filename_ptr.is_null() { return 0; }
    if let Some(mut entry) = EVENTS.reserve::<BpfEvent>(0) {
        let ev = entry.write(BpfEvent { pid, event_type: EVENT_TYPE_EXEC, resolved: 0, target: [0; 256] });
        let _ = unsafe { bpf_probe_read_user_str_bytes(filename_ptr, &mut ev.target) };
        entry.submit(0);
    }
    0
}

/// Intercepta sendto para detectar queries DNS (porta 53).
/// O payload bruto é armazenado no mapa PENDING_DNS_QUERY para userspace parsear.
///
/// Princípio verifier-safe: nenhuma escrita na stack com offset variável.
/// Toda escrita intermediária usa PerCpuArray (SCRATCH_DOMAIN) com slices de
/// tamanho estático que o verifier consegue provar.
///
/// Seção: "tracepoint/syscalls/sys_enter_sendto"
#[cfg(target_arch = "bpf")]
#[tracepoint(category = "syscalls", name = "sys_enter_sendto")]
pub fn handle_sendto(ctx: TracePointContext) -> u32 {
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    if !is_monitored(pid) { return 0; }

    let fd: i64 = unsafe { ctx.read_at(16) }.unwrap_or(0);
    let buff_ptr: *const u8 = match unsafe { ctx.read_at(24) } {
        Ok(ptr) => ptr,
        Err(_) => return 0,
    };
    if buff_ptr.is_null() { return 0; }
    let addr_ptr: *const u8 = unsafe { ctx.read_at(48) }.unwrap_or(core::ptr::null());

    // Detecta DNS: porta 53 em big-endian (0x3500 como u16 LE) ou fd marcado
    let is_dns = if !addr_ptr.is_null() {
        let port: u16 = unsafe { bpf_probe_read_user(addr_ptr.add(2) as *const u16) }.unwrap_or(0);
        port == 0x3500
    } else {
        let key = ((pid as u64) << 32) | (fd as u32 as u64);
        unsafe { DNS_FDS.get(&key) }.map(|v| *v == 1).unwrap_or(false)
    };
    if !is_dns { return 0; }

    let tx_id: u16 = match unsafe { bpf_probe_read_user(buff_ptr as *const u16) } {
        Ok(val) => val,
        Err(_) => return 0,
    };

    // Usa PerCpuArray (offset sempre estático) para capturar payload
    let scratch = SCRATCH_DOMAIN.get_ptr_mut(0);
    let scratch_ref = match scratch {
        Some(ptr) => unsafe { &mut *ptr },
        None => return 0,
    };
    // Zera com slice de tamanho fixo
    for b in scratch_ref[..256].iter_mut() { *b = 0; }
    let _ = unsafe { bpf_probe_read_user_buf(buff_ptr, &mut scratch_ref[..256]) };

    let mut payload = [0u8; 256];
    payload.copy_from_slice(&scratch_ref[..256]);
    let _ = PENDING_DNS_QUERY.insert(tx_id, &payload, 0);
    0
}

/// Registra ponteiro de buffer do recvfrom para correlacionar com resposta DNS.
/// Seção: "tracepoint/syscalls/sys_enter_recvfrom"
#[cfg(target_arch = "bpf")]
#[tracepoint(category = "syscalls", name = "sys_enter_recvfrom")]
pub fn handle_enter_recvfrom(ctx: TracePointContext) -> u32 {
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;
    if !is_monitored(pid) { return 0; }
    let ubuf_ptr: *const u8 = unsafe { ctx.read_at(24) }.unwrap_or(core::ptr::null());
    let _ = DNS_RECV_BUFF.insert(pid_tgid, &(ubuf_ptr as u64), 0);
    0
}

/// Captura resposta DNS (bytes brutos) e emite evento de rede com a resposta.
/// O parsing completo de Answer RRs e a inserção em IP_TO_DOMAIN é feito no userspace.
/// Seção: "tracepoint/syscalls/sys_exit_recvfrom"
#[cfg(target_arch = "bpf")]
#[tracepoint(category = "syscalls", name = "sys_exit_recvfrom")]
pub fn handle_exit_recvfrom(ctx: TracePointContext) -> u32 {
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;

    let buff_addr = match unsafe { DNS_RECV_BUFF.get(&pid_tgid) } {
        Some(val) => *val,
        None => return 0,
    };
    let _ = DNS_RECV_BUFF.remove(&pid_tgid);

    let ret: i64 = unsafe { ctx.read_at(16) }.unwrap_or(0);
    if ret <= 12 { return 0; }

    let buff_ptr = buff_addr as *const u8;
    let tx_id: u16 = match unsafe { bpf_probe_read_user(buff_ptr as *const u16) } {
        Ok(val) => val,
        Err(_) => return 0,
    };

    let _ = PENDING_DNS_QUERY.remove(&tx_id);

    // Emite evento com os bytes brutos da resposta DNS para o userspace parsear
    if let Some(mut entry) = EVENTS.reserve::<BpfEvent>(0) {
        let ev = entry.write(BpfEvent {
            pid,
            event_type: EVENT_TYPE_NETWORK,
            resolved: 1,
            target: [0; 256],
        });
        let _ = unsafe { bpf_probe_read_user_buf(buff_ptr, &mut ev.target) };
        entry.submit(0);
    }

    0
}

/// Intercepta connect(2) para detectar conexões de rede de saída.
/// Seção: "tracepoint/syscalls/sys_enter_connect"
#[cfg(target_arch = "bpf")]
#[tracepoint(category = "syscalls", name = "sys_enter_connect")]
pub fn handle_connect(ctx: TracePointContext) -> u32 {
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    if !is_monitored(pid) { return 0; }

    let fd: i64 = unsafe { ctx.read_at(16) }.unwrap_or(0);
    let uservaddr_ptr: *const u8 = match unsafe { ctx.read_at(24) } {
        Ok(ptr) => ptr,
        Err(_) => return 0,
    };
    if uservaddr_ptr.is_null() { return 0; }

    let family: u16 = match unsafe { bpf_probe_read_user(uservaddr_ptr as *const u16) } {
        Ok(val) => val,
        Err(_) => return 0,
    };

    // AF_UNIX = 1: socket local, ignorar
    if family == 1 { return 0; }

    // AF_INET6 = 10
    if family == 10 {
        let mut sa6 = [0u8; 28];
        let _ = unsafe { bpf_probe_read_user_buf(uservaddr_ptr, &mut sa6) };
        let port = ((sa6[2] as u16) << 8) | (sa6[3] as u16);
        if port == 53 {
            let key = ((pid as u64) << 32) | (fd as u32 as u64);
            let _ = DNS_FDS.insert(&key, &1u8, 0);
            return 0;
        }
        // Loopback IPv6 (::1)
        let is_lo = sa6[8..23].iter().all(|&b| b == 0) && sa6[23] == 1;
        // Link-local fe80::/10
        let is_ll = sa6[8] == 0xfe && (sa6[9] & 0xc0) == 0x80;
        if is_lo || is_ll { return 0; }

        if let Some(mut entry) = EVENTS.reserve::<BpfEvent>(0) {
            let ev = entry.write(BpfEvent { pid, event_type: EVENT_TYPE_NETWORK, resolved: 1, target: [0; 256] });
            let msg = b"<ipv6-nao-suportado>";
            ev.target[..20].copy_from_slice(msg);
            entry.submit(0);
        }
        return 0;
    }

    // AF_INET = 2
    if family != 2 { return 0; }

    let mut sa = [0u8; 16];
    let _ = unsafe { bpf_probe_read_user_buf(uservaddr_ptr, &mut sa) };

    let port = ((sa[2] as u16) << 8) | (sa[3] as u16);
    if port == 53 {
        let key = ((pid as u64) << 32) | (fd as u32 as u64);
        let _ = DNS_FDS.insert(&key, &1u8, 0);
        return 0;
    }

    // Loopback IPv4 (127.x.x.x): ignorar
    if sa[4] == 127 { return 0; }

    // IP em big-endian (como armazenado em sockaddr_in.sin_addr)
    let ip_be = ((sa[4] as u32) << 24)
        | ((sa[5] as u32) << 16)
        | ((sa[6] as u32) << 8)
        | (sa[7] as u32);

    if let Some(mut entry) = EVENTS.reserve::<BpfEvent>(0) {
        let ev = entry.write(BpfEvent {
            pid,
            event_type: EVENT_TYPE_NETWORK,
            resolved: 0,
            target: [0; 256],
        });
        if let Some(domain) = unsafe { IP_TO_DOMAIN.get(&ip_be) } {
            ev.resolved = 2;
            ev.target.copy_from_slice(domain);
        } else {
            // Encoda IP bruto com tag 0xAA para userspace decodificar
            ev.target[0] = 0xAA;
            ev.target[1] = sa[4];
            ev.target[2] = sa[5];
            ev.target[3] = sa[6];
            ev.target[4] = sa[7];
        }
        entry.submit(0);
    }
    0
}

#[cfg(target_arch = "bpf")]
#[inline(always)]
#[link_section = ".text"]
fn starts_with(path: &[u8; 256], prefix: &[u8; 128]) -> bool {
    for i in 0..128 {
        let p = prefix[i];
        if p == 0 {
            return true;
        }
        if path[i] != p {
            return false;
        }
    }
    true
}

#[cfg(target_arch = "bpf")]
#[inline(always)]
#[link_section = ".text"]
fn is_sensitive_path(path: &[u8; 256]) -> bool {
    // NOTA: Varremos até 240 bytes para ter lookahead seguro (até +6 bytes) sem
    // estourar os limites do array de 256 bytes e evitar falhas no verifier.
    for i in 0..240 {
        let b = path[i];
        if b == 0 {
            break;
        }

        // 1. Checar se contém ".env" (exclui falsos positivos como .env.example ou .environment)
        if b == b'.' && path[i+1] == b'e' && path[i+2] == b'n' && path[i+3] == b'v' {
            let is_start = i == 0 || path[i-1] == b'/';
            let is_end = path[i+4] == 0 || path[i+4] == b'/';
            if is_start && is_end {
                return true;
            }
        }

        // 2. Checar se contém ".ssh" (exclui falsos positivos como .ssh-key)
        if b == b'.' && path[i+1] == b's' && path[i+2] == b's' && path[i+3] == b'h' {
            let is_start = i == 0 || path[i-1] == b'/';
            let is_end = path[i+4] == 0 || path[i+4] == b'/';
            if is_start && is_end {
                return true;
            }
        }

        // 3. Checar "id_rsa"
        if b == b'i' && path[i+1] == b'd' && path[i+2] == b'_' && path[i+3] == b'r' && path[i+4] == b's' && path[i+5] == b'a' {
            let is_start = i == 0 || path[i-1] == b'/';
            let is_end = path[i+6] == 0 || path[i+6] == b'/';
            if is_start && is_end {
                return true;
            }
        }

        // 4. Checar extensão ".pem" no final do arquivo
        if b == b'.' && path[i+1] == b'p' && path[i+2] == b'e' && path[i+3] == b'm' {
            let is_end = path[i+4] == 0;
            if is_end {
                return true;
            }
        }
    }
    false
}

#[cfg(target_arch = "bpf")]
#[inline(always)]
#[link_section = ".text"]
fn report_fs_event(pid: u32, is_write: bool, buf: &[u8; 256]) {
    if let Some(mut entry) = EVENTS.reserve::<BpfEvent>(0) {
        let ev = entry.as_mut_ptr();
        unsafe {
            (*ev).pid = pid;
            (*ev).event_type = if is_write { EVENT_TYPE_WRITE } else { EVENT_TYPE_READ };
            (*ev).resolved = 0;
            for i in 0..256 {
                (*ev).target[i] = buf[i];
            }
        }
        entry.submit(0);
    }
}

#[cfg(target_arch = "bpf")]
#[lsm(hook = "file_open")]
pub fn lsm_file_open(ctx: LsmContext) -> i32 {
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    if !is_monitored(pid) {
        return 0;
    }

    let file_ptr: *mut file = ctx.arg(0);
    if file_ptr.is_null() {
        return 0;
    }

    // Acesso de campo direto (não offset manual + soma de ponteiro): preserva
    // a proveniência de tipo BTF exigida por bpf_d_path. Ver GT-13.
    let path_ptr = unsafe { &raw mut (*file_ptr).f_path };

    let scratch_ptr = match SCRATCH_PATH.get_ptr_mut(0) {
        Some(ptr) => ptr,
        None => return 0,
    };
    if scratch_ptr.is_null() {
        return 0;
    }
    let buf: &mut [u8; 256] = unsafe { &mut *scratch_ptr };
    for i in 0..256 {
        buf[i] = 0;
    }

    let ret = unsafe { bpf_d_path(path_ptr as *mut aya_ebpf::bindings::path, buf.as_mut_ptr() as *mut i8, 256) };
    if ret < 0 {
        return -13; // -EACCES
    }

    let f_mode_offset = get_f_mode_offset();
    let f_mode: u32 = unsafe {
        match aya_ebpf::helpers::bpf_probe_read_kernel((file_ptr as *const u8).add(f_mode_offset as usize) as *const u32) {
            Ok(v) => v,
            Err(_) => 0,
        }
    };
    let is_write = (f_mode & 2) != 0; // FMODE_WRITE

    // 1. Verificar caminhos sensíveis proibidos por especificação (.env, .ssh/, etc.)
    if is_sensitive_path(buf) {
        if is_enforce_mode() {
            return -13; // -EACCES
        } else {
            report_fs_event(pid, is_write, buf);
            return 0; // Monitor-only: permite a operação
        }
    }

    // 2. Verificar regras globais de negação (DENY_ALWAYS)
    for i in 0..16 {
        if let Some(prefix) = unsafe { DENY_ALWAYS_PREFIXES.get(&i) } {
            if prefix[0] != 0 && starts_with(buf, prefix) {
                if is_enforce_mode() {
                    return -13; // -EACCES
                } else {
                    report_fs_event(pid, is_write, buf);
                    return 0; // Monitor-only: permite
                }
            }
        }
    }

    // 3. Verificar se o caminho está permitido nas allowlists
    if is_write {
        for i in 0..16 {
            if let Some(prefix) = unsafe { ALLOW_WRITE_PREFIXES.get(&i) } {
                if prefix[0] != 0 && starts_with(buf, prefix) {
                    return 0; // Permitido
                }
            }
        }
    } else {
        for i in 0..16 {
            if let Some(prefix) = unsafe { ALLOW_READ_PREFIXES.get(&i) } {
                if prefix[0] != 0 && starts_with(buf, prefix) {
                    return 0; // Permitido
                }
            }
        }
    }

    // 4. Default: Negado (Zero Trust)
    if is_enforce_mode() {
        -13 // -EACCES
    } else {
        report_fs_event(pid, is_write, buf);
        0 // Monitor-only: permite
    }
}

#[cfg(target_arch = "bpf")]
#[inline(always)]
#[link_section = ".text"]
fn report_exec_event(pid: u32, buf: &[u8; 256]) {
    if let Some(mut entry) = EVENTS.reserve::<BpfEvent>(0) {
        let ev = entry.as_mut_ptr();
        unsafe {
            (*ev).pid = pid;
            (*ev).event_type = EVENT_TYPE_EXEC;
            (*ev).resolved = 0;
            for i in 0..256 {
                (*ev).target[i] = buf[i];
            }
        }
        entry.submit(0);
    }
}

#[cfg(target_arch = "bpf")]
#[lsm(hook = "bprm_check_security")]
pub fn lsm_exec_check(ctx: LsmContext) -> i32 {
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    if !is_monitored(pid) {
        return 0;
    }

    let bprm: *mut linux_binprm = ctx.arg(0);
    if bprm.is_null() {
        return 0;
    }

    let file_ptr = unsafe { (*bprm).file };
    if file_ptr.is_null() {
        return 0;
    }

    // Mesmo padrão de lsm_file_open: acesso de campo direto preserva tipo BTF. GT-13.
    let path_ptr = unsafe { &raw mut (*file_ptr).f_path };

    let scratch_ptr = match SCRATCH_PATH.get_ptr_mut(0) {
        Some(ptr) => ptr,
        None => return 0,
    };
    if scratch_ptr.is_null() {
        return 0;
    }
    let buf: &mut [u8; 256] = unsafe { &mut *scratch_ptr };
    for i in 0..256 {
        buf[i] = 0;
    }

    let ret = unsafe { bpf_d_path(path_ptr as *mut aya_ebpf::bindings::path, buf.as_mut_ptr() as *mut i8, 256) };
    if ret < 0 {
        return -13; // -EACCES
    }

    for i in 0..16 {
        if let Some(rule) = unsafe { DENY_SYSCALLS_RULES.get(&i) } {
            if rule.pattern[0] != 0 {
                if rule.pattern[0] == b'e' && rule.pattern[1] == b'x' && rule.pattern[2] == b'e' 
                    && rule.pattern[3] == b'c' && rule.pattern[4] == b'v' && rule.pattern[5] == b'e' 
                    && rule.pattern[6] == b':' 
                {
                    let mut pattern_offset = [0u8; 128];
                    for j in 0..120 {
                        pattern_offset[j] = rule.pattern[j + 7];
                    }
                    if starts_with(buf, &pattern_offset) {
                        if is_enforce_mode() {
                            if rule.kill_on_deny == 1 {
                                unsafe { bpf_send_signal(9) }; // SIGKILL
                            }
                            return -13; // -EACCES
                        } else {
                            report_exec_event(pid, buf);
                            return 0; // Monitor-only: permite
                        }
                    }
                }
            }
        }
    }

    0
}

#[cfg(target_arch = "bpf")]
#[tracepoint(category = "syscalls", name = "sys_enter_ptrace")]
pub fn handle_ptrace(_ctx: TracePointContext) -> u32 {
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    if !is_monitored(pid) {
        return 0;
    }

    if let Some(mut entry) = EVENTS.reserve::<BpfEvent>(0) {
        let ev = entry.write(BpfEvent {
            pid,
            event_type: EVENT_TYPE_SYSCALL,
            resolved: 0,
            target: [0; 256],
        });
        let ptrace_str = b"ptrace";
        for i in 0..ptrace_str.len() {
            ev.target[i] = ptrace_str[i];
        }
        entry.submit(0);
    }
    0
}

#[cfg(not(target_arch = "bpf"))]
fn main() {}

#[cfg(target_arch = "bpf")]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
