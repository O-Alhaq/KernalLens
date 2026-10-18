#ifndef KERNELLENS_HOST_EVENT_H
#define KERNELLENS_HOST_EVENT_H

enum host_event_kind {
    HOST_PROCESS_EXEC = 1,
    HOST_SYSCALL = 2,
    HOST_PRIVILEGE_CHANGE = 3,
};

enum host_syscall {
    HOST_NO_SYSCALL = 0,
    HOST_SETUID = 1,
    HOST_SETGID = 2,
};

/* A separate record type preserves the existing network ABI. UID/GID are
 * effective IDs in the kernel's initial user namespace, not requested IDs. */
struct host_event {
    __u64 timestamp;
    __s64 syscall_return;
    __u32 kind;
    __u32 syscall;
    __u32 pid;
    __u32 ppid;
    __u32 uid;
    __u32 gid;
    __u32 previous_uid;
    __u32 previous_gid;
    char process_name[16];
    char process_path[256];
};

_Static_assert(sizeof(struct host_event) == 320, "host event ABI mismatch");

#endif
