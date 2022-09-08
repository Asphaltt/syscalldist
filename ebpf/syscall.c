#include "vmlinux.h"

#include "bpf_core_read.h"
#include "bpf_helpers.h"

#include "bits.bpf.h"
#include "maps.bpf.h"

char __license[] SEC("license") = "GPL";

#define MAX_SLOTS 36

static volatile const __u32 filter_pid = 0;
static volatile const __u32 filter_syscall_id = 0;

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 1024);
} clocks SEC(".maps");

struct hist {
    __u64 slots[MAX_SLOTS];
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct hist);
    __uint(max_entries, 1);
} hists SEC(".maps");

SEC("raw_tracepoint/sys_enter")
int sys_enter(struct bpf_raw_tracepoint_args *ctx)
{
    __u64 syscall_id = ctx->args[1];
    if (syscall_id != filter_syscall_id)
        return 0;

    __u32 pid = (__u32)bpf_get_current_pid_tgid();
    if (pid != filter_pid)
        return 0;

    __u64 ts = bpf_ktime_get_ns();
    bpf_map_update_elem(&clocks, &pid, &ts, BPF_ANY);

    return 0;
}

SEC("raw_tracepoint/sys_exit")
int sys_exit(struct bpf_raw_tracepoint_args *ctx)
{
    struct pt_regs *args = (struct pt_regs *)ctx->args[0];
    __u64 syscall_id = BPF_CORE_READ(args, orig_ax);
    if (syscall_id != filter_syscall_id)
        return 0;

    __u32 pid = (__u32)bpf_get_current_pid_tgid();
    if (pid != filter_pid)
        return 0;

    __u64 *tsp = bpf_map_lookup_and_delete(&clocks, &pid);
    if (!tsp)
        return 0;

    struct hist initial_hist = {};
    __u32 index = 0;
    struct hist *hp = bpf_map_lookup_or_try_init(&hists, &index, &initial_hist);
    if (!hp)
        return 0;

    __u64 delta = bpf_ktime_get_ns() - *tsp;
    delta /= 1000; // micro-second
    __u64 slot = log2l(delta);
    if (slot >= MAX_SLOTS)
        slot = MAX_SLOTS - 1;
    __sync_fetch_and_add(&hp->slots[slot], 1);

    return 0;
}