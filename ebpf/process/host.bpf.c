#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include "host_event.h"

/* The agent reuses the network program's map FD before loading this object. */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

struct credential_call {
    __u32 syscall;
    __u32 uid;
    __u32 gid;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u64);
    __type(value, struct credential_call);
} pending SEC(".maps");

static __always_inline void credentials(__u32 *uid, __u32 *gid)
{
    struct task_struct *task = (void *)bpf_get_current_task_btf();

    *uid = BPF_CORE_READ(task, cred, euid.val);
    *gid = BPF_CORE_READ(task, cred, egid.val);
}

static __always_inline struct host_event *new_event(__u32 kind, __u32 syscall)
{
    struct host_event *event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    struct task_struct *task;

    if (!event)
        return 0;
    __builtin_memset(event, 0, sizeof(*event));
    task = (void *)bpf_get_current_task_btf();
    event->timestamp = bpf_ktime_get_ns();
    event->kind = kind;
    event->syscall = syscall;
    event->pid = bpf_get_current_pid_tgid() >> 32;
    event->ppid = BPF_CORE_READ(task, real_parent, tgid);
    credentials(&event->uid, &event->gid);
    bpf_get_current_comm(event->process_name, sizeof(event->process_name));
    return event;
}

SEC("tracepoint/sched/sched_process_exec")
int host_exec(struct trace_event_raw_sched_process_exec *context)
{
    struct host_event *event = new_event(HOST_PROCESS_EXEC, HOST_NO_SYSCALL);
    __u32 offset;

    if (!event)
        return 0;
    offset = context->__data_loc_filename & 0xffff;
    if (bpf_probe_read_kernel_str(event->process_path, sizeof(event->process_path),
                                  (void *)context + offset) < 0)
        event->process_path[0] = '\0';
    bpf_ringbuf_submit(event, 0);
    return 0;
}

static __always_inline int enter_credential_call(__u32 syscall)
{
    __u64 key = bpf_get_current_pid_tgid();
    struct credential_call call = { .syscall = syscall };

    credentials(&call.uid, &call.gid);
    bpf_map_update_elem(&pending, &key, &call, BPF_ANY);
    return 0;
}

static __always_inline int exit_credential_call(struct trace_event_raw_sys_exit *context,
                                               __u32 syscall)
{
    __u64 key = bpf_get_current_pid_tgid();
    struct credential_call *stored = bpf_map_lookup_elem(&pending, &key);
    struct credential_call call;
    struct host_event *event;
    __u32 uid, gid;

    if (!stored)
        return 0;
    call = *stored;
    bpf_map_delete_elem(&pending, &key);
    if (call.syscall != syscall)
        return 0;
    event = new_event(HOST_SYSCALL, syscall);
    if (event) {
        event->syscall_return = context->ret;
        bpf_ringbuf_submit(event, 0);
    }
    credentials(&uid, &gid);
    if (context->ret == 0 && (uid != call.uid || gid != call.gid)) {
        event = new_event(HOST_PRIVILEGE_CHANGE, syscall);
        if (event) {
            event->syscall_return = 0;
            event->previous_uid = call.uid;
            event->previous_gid = call.gid;
            bpf_ringbuf_submit(event, 0);
        }
    }
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_setuid")
int enter_setuid(void *context)
{
    return enter_credential_call(HOST_SETUID);
}

SEC("tracepoint/syscalls/sys_exit_setuid")
int exit_setuid(struct trace_event_raw_sys_exit *context)
{
    return exit_credential_call(context, HOST_SETUID);
}

SEC("tracepoint/syscalls/sys_enter_setgid")
int enter_setgid(void *context)
{
    return enter_credential_call(HOST_SETGID);
}

SEC("tracepoint/syscalls/sys_exit_setgid")
int exit_setgid(struct trace_event_raw_sys_exit *context)
{
    return exit_credential_call(context, HOST_SETGID);
}

/* Bound entry/exit state to the thread lifetime, even for interrupted calls. */
SEC("tracepoint/sched/sched_process_exit")
int host_exit(void *context)
{
    __u64 key = bpf_get_current_pid_tgid();

    bpf_map_delete_elem(&pending, &key);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
