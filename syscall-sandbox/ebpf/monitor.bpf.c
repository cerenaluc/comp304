
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

// we need this to send data to userspace
struct syscall_event {
    __u32 pid;
    __u32 syscall_nr;
    __u64 timestamp_ns;
// process name, 16 bytes is the limit i think
    char comm[16];
};

// map to keep track of which pids we are watching we are using hash map, max 1024 entries 
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);
// just 1 or 0
    __type(value, __u8);
} tracked_pids SEC(".maps");

// same idea but for syscall numbers
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, __u8);
} watched_syscalls SEC(".maps");


// ring buffer to send events to userspace, we decided to use 16mb
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");

struct sys_enter_args {
    unsigned long long unused; // padding, first field is always unused
    long id;
    unsigned long args[6];
};

SEC("tracepoint/raw_syscalls/sys_enter")
int handle_sys_enter(struct sys_enter_args *ctx) {

// we shift by 32 because upper 32 bits is pid, lower is tid
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u32 syscall = (__u32)ctx->id;

// check if we care about this pid, if not just return
    __u8 *pid_exists = bpf_map_lookup_elem(&tracked_pids, &pid);
    if (!pid_exists)
        return 0;

// also check if this syscall is in our watch list
    __u8 *sys_exists = bpf_map_lookup_elem(&watched_syscalls, &syscall);
    if (!sys_exists)
        return 0;

// both matched so we send an event to userspace
    struct syscall_event *e;
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    e->pid = pid;
    e->syscall_nr = syscall;
    e->timestamp_ns = bpf_ktime_get_ns();
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    bpf_ringbuf_submit(e, 0);

    return 0;
}
