/* Exercise the production IPC module without requiring BPF privileges. */
#include <stdio.h>
#include <arpa/inet.h>
#include <string.h>
#include "ipc.h"

int main(int argc, char **argv)
{
    struct ipc_server server;
    struct packet_event event = {
        .timestamp = 123456789, .ifindex = 2, .packet_length = 86,
        .src_port = 45678, .dst_port = 80, .protocol = 6,
        .tcp_flags = 2, .ip_version = 4,
    };
    char command[32];

    inet_pton(AF_INET, "192.0.2.1", &event.src_ip);
    inet_pton(AF_INET, "192.0.2.2", &event.dst_ip);

    if (argc != 2 || ipc_open(&server, argv[1]))
        return 1;
    setvbuf(stdout, NULL, _IOLBF, 0);
    puts("ready");
    while (fgets(command, sizeof(command), stdin)) {
        int error = 0;
        struct host_event host = {
            .timestamp = 123456789, .kind = HOST_PROCESS_EXEC,
            .pid = 4217, .ppid = 4100, .uid = 1000, .gid = 1000,
            .process_name = "host-helper", .process_path = "/usr/bin/true",
        };

        if (!strcmp(command, "quit\n"))
            break;
        ipc_poll(&server);
        if (!strcmp(command, "event\n"))
            error = ipc_route_event(&server, &event, sizeof(event));
        if (!strcmp(command, "flood\n"))
            for (int i = 0; i < 100000; i++)
                ipc_route_event(&server, &event, sizeof(event));
        if (!strncmp(command, "host_", 5)) {
            if (!strcmp(command, "host_syscall\n") || !strcmp(command, "host_privilege\n")) {
                host.kind = HOST_SYSCALL;
                host.syscall = HOST_SETUID;
                host.syscall_return = -1;
                host.process_path[0] = '\0';
            }
            if (!strcmp(command, "host_privilege\n")) {
                host.kind = HOST_PRIVILEGE_CHANGE;
                host.syscall_return = 0;
                host.previous_uid = 0;
                host.previous_gid = 1000;
            }
            if (!strcmp(command, "host_escape\n")) {
                strcpy(host.process_name, "a\"\\\n\xff");
                strcpy(host.process_path, "/tmp/a\"\\\n\xff");
            }
            if (!strcmp(command, "host_max\n")) {
                memset(host.process_path, 0xff, sizeof(host.process_path) - 1);
                memset(host.process_name, 0xff, sizeof(host.process_name) - 1);
            }
            if (!strcmp(command, "host_bad_kind\n"))
                host.kind = 999;
            if (!strcmp(command, "host_bad_syscall\n")) {
                host.kind = HOST_SYSCALL;
                host.syscall = 999;
            }
            error = ipc_route_event(&server, &host, sizeof(host));
        }
        if (!strcmp(command, "bad_size\n"))
            error = ipc_route_event(&server, &host, 1);
        puts(error ? "rejected" : "ok");
    }
    ipc_close(&server);
    return 0;
}
