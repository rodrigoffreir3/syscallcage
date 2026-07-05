//go:build ignore

#include <linux/bpf.h>
#include <asm/ptrace.h>
#include <stdbool.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

char __license[] SEC("license") = "Dual MIT/GPL";

typedef unsigned int u32;
typedef unsigned long long u64;
typedef unsigned char u8;
typedef unsigned short u16;

// O tipo de evento reflete as regras da policy (Read, Write, Exec, Network)
#define EVENT_TYPE_READ 1
#define EVENT_TYPE_WRITE 2
#define EVENT_TYPE_EXEC 3
#define EVENT_TYPE_NETWORK 4

// Estrutura do evento enviada via Ring Buffer para o Go (Userspace)
struct event {
    u32 pid;
    u32 type;
    u8 resolved;
    u8 target[256];
};

struct event *unused __attribute__((unused));

// =========================================================================
// BPF MAPS
// =========================================================================

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24); // 16MB
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, u32);
    __type(value, u8);
} monitored_pids SEC(".maps");

// LRU_HASH para prevenir vazamento de memória com queries abandonadas
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 1024);
    __type(key, u16); // Transaction ID
    __type(value, u8[256]); // Domínio
} pending_dns_query SEC(".maps");

// LRU_HASH para previnir threads mortas mid-syscall e vazar
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 1024);
    __type(key, u64); // PID_TGID completo
    __type(value, void *);
} dns_recv_buff SEC(".maps");

// LRU_HASH para expirar IPs de DNS antigos automaticamente
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 4096);
    __type(key, u32);
    __type(value, u8[256]);
} ip_to_domain SEC(".maps");

// PERCPU_ARRAY como scratch buffer para parsing de domínio, 
// resolvendo o erro 'invalid variable-offset write to stack'
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, u8[512]);
} scratch_domain SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 1024);
    __type(key, u64); // (pid << 32) | fd
    __type(value, u8);
} dns_fds SEC(".maps");



// =========================================================================
// TRACEPOINTS: PROCESS LIFECYCLE (Fork & Exit)
// =========================================================================
struct task_struct {
    int tgid;
} __attribute__((preserve_access_index));

SEC("kprobe/wake_up_new_task")
int handle_wake_up_new_task(struct pt_regs *ctx) {
    struct task_struct *task = (struct task_struct *)PT_REGS_PARM1(ctx);
    u32 child_pid = 0;
    bpf_core_read(&child_pid, sizeof(child_pid), &task->tgid);

    u32 parent_pid = bpf_get_current_pid_tgid() >> 32;
    u8 *is_monitored = bpf_map_lookup_elem(&monitored_pids, &parent_pid);
    if (is_monitored && *is_monitored == 1) {
        u8 val = 1;
        bpf_map_update_elem(&monitored_pids, &child_pid, &val, BPF_ANY);
    }
    return 0;
}

struct trace_event_raw_sched_process_template {
    unsigned long long unused;
    char comm[16];
    int pid;
    int prio;
};

SEC("tracepoint/sched/sched_process_exit")
int handle_exit(struct trace_event_raw_sched_process_template *ctx) {
    u32 pid = ctx->pid;
    bpf_map_delete_elem(&monitored_pids, &pid);
    return 0;
}

// =========================================================================
// INTERCEPTAÇÃO DE FILE OPEN (Kprobe em do_sys_openat2)
// Usamos Kprobe em vez de tracepoint para garantir estabilidade no WSL2
// e evitar problemas de alinhamento de struct entre diferentes kernels.
// =========================================================================
SEC("kprobe/do_sys_openat2")
int handle_openat2(struct pt_regs *ctx) {
    const char *filename = (const char *)PT_REGS_PARM2(ctx);
    
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    
    u8 *is_monitored = bpf_map_lookup_elem(&monitored_pids, &pid);
    if (!is_monitored || *is_monitored == 0) return 0;

    struct event *e = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
    if (!e) return 0;

    e->pid = pid;
    e->resolved = false;
    e->type = EVENT_TYPE_READ;

    long ret = bpf_probe_read_user_str(&e->target, sizeof(e->target), filename);
    if (ret < 0) {
        __builtin_memcpy(e->target, "<erro_leitura>", 14);
        e->target[14] = '\0';
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("kprobe/do_sys_open")
int handle_open(struct pt_regs *ctx) {
    const char *filename = (const char *)PT_REGS_PARM2(ctx);
    
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    
    u8 *is_monitored = bpf_map_lookup_elem(&monitored_pids, &pid);
    if (!is_monitored || *is_monitored == 0) return 0;

    struct event *e = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
    if (!e) return 0;

    e->pid = pid;
    e->resolved = false;
    e->type = EVENT_TYPE_READ;

    long ret = bpf_probe_read_user_str(&e->target, sizeof(e->target), filename);
    if (ret < 0) {
        __builtin_memcpy(e->target, "<erro_leitura>", 14);
        e->target[14] = '\0';
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// =========================================================================
// TRACEPOINT: execve
// =========================================================================
struct trace_event_raw_sys_enter_execve {
    unsigned long long unused;
    long __syscall_nr;
    const char *filename;
    const char *const *argv;
    const char *const *envp;
};

SEC("tracepoint/syscalls/sys_enter_execve")
int handle_execve(struct trace_event_raw_sys_enter_execve *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    
    u8 *is_monitored = bpf_map_lookup_elem(&monitored_pids, &pid);
    if (!is_monitored || *is_monitored == 0) return 0;

    struct event *e = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
    if (!e) return 0;

    e->pid = pid;
    e->type = EVENT_TYPE_EXEC;
    
    long ret = bpf_probe_read_user_str(&e->target, sizeof(e->target), ctx->filename);
    if (ret < 0) {
        __builtin_memcpy(e->target, "<erro_leitura>", 14);
        e->target[14] = '\0';
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// =========================================================================
// TRACEPOINT: DNS Snooping (sendto & recvfrom)
// =========================================================================

struct trace_event_raw_sys_enter_sendto {
    unsigned long long unused;
    long __syscall_nr;
    long fd;
    void * buff;
    long len;
    long flags;
    struct sockaddr * addr;
    long addr_len;
};

SEC("tracepoint/syscalls/sys_enter_sendto")
int handle_sendto(struct trace_event_raw_sys_enter_sendto *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u8 *is_monitored = bpf_map_lookup_elem(&monitored_pids, &pid);
    if (!is_monitored || *is_monitored == 0) return 0;

    u16 port = 0;
    bool is_dns = false;
    if (ctx->addr) {
        bpf_probe_read_user(&port, 2, (u8*)ctx->addr + 2); 
        if (port == 0x3500) {
            is_dns = true;
        }
    } else {
        u64 key = ((u64)pid << 32) | (u32)ctx->fd;
        u8 *val = bpf_map_lookup_elem(&dns_fds, &key);
        if (val && *val == 1) {
            is_dns = true;
        }
    }
    if (!is_dns) return 0;

    // Extrair Transaction ID (2 primeiros bytes)
    u16 tx_id = 0;
    bpf_probe_read_user(&tx_id, 2, ctx->buff);

    u32 zero = 0;
    u8 *domain = bpf_map_lookup_elem(&scratch_domain, &zero);
    if (!domain) return 0;
    
    // Zera o array de scratch (já que é reusado entre chamadas)
    __builtin_memset(domain, 0, 256);

    int offset = 12; // Pula DNS header
    int out_idx = 0;

    #pragma unroll
    for (int i = 0; i < 10; i++) {
        u8 len = 0;
        bpf_probe_read_user(&len, 1, (u8*)ctx->buff + offset);
        if (len == 0 || offset >= 250) break;
        
        offset++;
        if (out_idx > 0 && out_idx < 255) {
            domain[out_idx++] = '.';
        }

        if (len > 63) len = 63;
        out_idx &= 0xff;
        if (out_idx + len >= 255) break;
        
        // __builtin_constant_p or verifier tricks sometimes require len to be static,
        // but bpf_probe_read_user accepts dynamic sizes. 
        // We mask out_idx to [0, 255] and ensure out_idx + len < 255.
        bpf_probe_read_user(&domain[out_idx], len, (u8*)ctx->buff + offset);
        
        out_idx += len;
        offset += len;
    }

    if (out_idx > 0) {
        bpf_map_update_elem(&pending_dns_query, &tx_id, domain, BPF_ANY);
    }
    return 0;
}

struct trace_event_raw_sys_enter_recvfrom {
    unsigned long long unused;
    long __syscall_nr;
    long fd;
    void * ubuf;
    long size;
    long flags;
    struct sockaddr * addr;
    long addr_len;
};

SEC("tracepoint/syscalls/sys_enter_recvfrom")
int handle_enter_recvfrom(struct trace_event_raw_sys_enter_recvfrom *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u8 *is_monitored = bpf_map_lookup_elem(&monitored_pids, &pid);
    if (is_monitored && *is_monitored == 1) {
        void *buff = ctx->ubuf;
        bpf_map_update_elem(&dns_recv_buff, &pid_tgid, &buff, BPF_ANY);
    }
    return 0;
}

struct trace_event_raw_sys_exit_recvfrom {
    unsigned long long unused;
    long __syscall_nr;
    long ret;
};

SEC("tracepoint/syscalls/sys_exit_recvfrom")
int handle_exit_recvfrom(struct trace_event_raw_sys_exit_recvfrom *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    void **buff_ptr = bpf_map_lookup_elem(&dns_recv_buff, &pid_tgid);
    if (!buff_ptr) return 0;
    
    void *buff = *buff_ptr;
    bpf_map_delete_elem(&dns_recv_buff, &pid_tgid);
    
    if (ctx->ret <= 12) return 0; 

    // Recuperar Transaction ID para casar com a query
    u16 tx_id = 0;
    bpf_probe_read_user(&tx_id, 2, buff);
    
    u8 *domain = bpf_map_lookup_elem(&pending_dns_query, &tx_id);
    if (!domain) return 0; 

    int offset = 12; // Pula o header (12 bytes)

    // Pular Question Section (QNAME)
    #pragma unroll
    for (int i = 0; i < 10; i++) {
        if (offset >= 250) break;
        u8 l = 0;
        bpf_probe_read_user(&l, 1, buff + offset);
        if (l == 0) {
            offset++;
            break;
        }
        // Tratamento de pointer de compressão
        if ((l & 0xC0) == 0xC0) {
            offset += 2;
            break;
        }
        offset += l + 1;
    }
    offset += 4; // Pular QTYPE e QCLASS

    // Parsing estruturado da Answer Section
    u32 ip = 0;
    #pragma unroll
    for (int i = 0; i < 5; i++) {
        if (offset >= 280) break;
        
        // Pular name (geralmente pointer 0xC0 XX)
        u8 l = 0;
        bpf_probe_read_user(&l, 1, buff + offset);
        if ((l & 0xC0) == 0xC0) {
            offset += 2;
        } else {
            break; // Fallback se não for pointer, evita complexidade
        }
        
        u8 buf4[4];
        bpf_probe_read_user(buf4, 4, buff + offset);
        u16 type = (buf4[0] << 8) | buf4[1];
        u16 class = (buf4[2] << 8) | buf4[3];
        offset += 4; // type e class
        offset += 4; // ttl
        
        u8 buf2[2];
        bpf_probe_read_user(buf2, 2, buff + offset);
        u16 rdlen = (buf2[0] << 8) | buf2[1];
        offset += 2;
        
        if (type == 1 && class == 1 && rdlen == 4) { // A Record (IPv4)
            bpf_probe_read_user(&ip, 4, buff + offset);
            break; 
        }
        
        offset += rdlen; // Se for CNAME, pula o conteúdo e checa o próximo record
    }

    if (ip != 0) {
        bpf_map_update_elem(&ip_to_domain, &ip, domain, BPF_ANY);
    }
    
    bpf_map_delete_elem(&pending_dns_query, &tx_id);
    return 0;
}

// =========================================================================
// TRACEPOINT: connect (Rede)
// =========================================================================

#define AF_INET 2

struct sockaddr_in_bpf {
    u16 sin_family;
    u16 sin_port;
    u32 sin_addr; 
    u8  sin_zero[8];
};

struct sockaddr_in6_bpf {
    u16 sin6_family;
    u16 sin6_port;
    u32 sin6_flowinfo;
    u8  sin6_addr[16];
    u32 sin6_scope_id;
};

struct trace_event_raw_sys_enter_connect {
    unsigned long long unused;
    long __syscall_nr;
    long fd;
    struct sockaddr_in_bpf *uservaddr;
    long addrlen;
};

SEC("tracepoint/syscalls/sys_enter_connect")
int handle_connect(struct trace_event_raw_sys_enter_connect *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    
    u8 *is_monitored = bpf_map_lookup_elem(&monitored_pids, &pid);
    if (!is_monitored || *is_monitored == 0) return 0;

    u16 family = 0;
    long ret = bpf_probe_read_user(&family, 2, ctx->uservaddr);

    if (family == 1) { // AF_UNIX / AF_LOCAL (permitir comunicação local)
        return 0;
    }

    if (family == 10) { // AF_INET6
        struct sockaddr_in6_bpf sa6 = {0};
        bpf_probe_read_user(&sa6, sizeof(sa6), ctx->uservaddr);

        // Permitir DNS queries via IPv6 (porta 53) e salvar FD
        if (sa6.sin6_port == 0x3500) {
            u64 key = ((u64)pid << 32) | (u32)ctx->fd;
            u8 val = 1;
            bpf_map_update_elem(&dns_fds, &key, &val, BPF_ANY);
            return 0;
        }

        // Permitir loopback (::1)
        bool is_loopback = true;
        #pragma unroll
        for (int i = 0; i < 15; i++) {
            if (sa6.sin6_addr[i] != 0) {
                is_loopback = false;
            }
        }
        if (sa6.sin6_addr[15] != 1) {
            is_loopback = false;
        }
        if (is_loopback) {
            return 0;
        }

        // Permitir link-local (fe80::/10)
        if (sa6.sin6_addr[0] == 0xfe && (sa6.sin6_addr[1] & 0xc0) == 0x80) {
            return 0;
        }
    }

    struct sockaddr_in_bpf sa = {0};
    bpf_probe_read_user(&sa, sizeof(sa), ctx->uservaddr);

    if (sa.sin_port == 0x3500) { // Permitir DNS IPv4 (porta 53) e salvar FD
        u64 key = ((u64)pid << 32) | (u32)ctx->fd;
        u8 val = 1;
        bpf_map_update_elem(&dns_fds, &key, &val, BPF_ANY);
        return 0;
    }

    if (sa.sin_family != AF_INET) {
        struct event *e = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
        if (e) {
            e->pid = pid;
            e->type = EVENT_TYPE_NETWORK;
            e->resolved = 1; 
            __builtin_memcpy(e->target, "<ipv6-nao-suportado>", 21);
            bpf_ringbuf_submit(e, 0);
        }
        return 0; 
    }

    u32 ip = sa.sin_addr;
    if ((ip & 0xFF) == 127) { // Permitir loopback (127.0.0.0/8)
        return 0;
    }

    struct event *e = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
    if (!e) return 0;

    e->pid = pid;
    e->type = EVENT_TYPE_NETWORK;

    u8 *domain = bpf_map_lookup_elem(&ip_to_domain, &ip);

    if (domain) {
        e->resolved = 1;
        __builtin_memcpy(e->target, domain, 256);
    } else {
        e->resolved = 0;
        e->target[0] = 0xAA;
        e->target[1] = ip & 0xFF;
        e->target[2] = (ip >> 8) & 0xFF;
        e->target[3] = (ip >> 16) & 0xFF;
        e->target[4] = (ip >> 24) & 0xFF;
        e->target[5] = '\0';
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}
