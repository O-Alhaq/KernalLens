/* Only this short-lived test process changes credentials. No host response. */
#include <errno.h>
#include <stdio.h>
#include <unistd.h>

int main(void)
{
    gid_t target_gid = getegid() == 65534 ? 65533 : 65534;

    if (geteuid() != 0) {
        fprintf(stderr, "Host integration helper requires root\n");
        return 1;
    }
    printf("{\"pid\":%ld,\"ppid\":%ld,\"old_uid\":%lu,\"old_gid\":%lu,"
           "\"target_uid\":65534,\"target_gid\":%lu}\n",
           (long)getpid(), (long)getppid(), (unsigned long)geteuid(),
           (unsigned long)getegid(), (unsigned long)target_gid);
    fflush(stdout);
    if (setgid(target_gid) || setuid(65534)) {
        perror("test credential drop");
        return 1;
    }
    if (setuid(65534)) { /* Successful no-op: syscall record, no privilege record. */
        perror("test no-op setuid");
        return 1;
    }
    if (setuid(0) != -1 || errno != EPERM) {
        fprintf(stderr, "Expected setuid(0) to be denied after permanent drop\n");
        return 1;
    }
    return 0;
}
