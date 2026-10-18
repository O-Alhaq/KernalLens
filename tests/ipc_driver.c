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
        if (!strcmp(command, "quit\n"))
            break;
        ipc_poll(&server);
        if (!strcmp(command, "event\n"))
            ipc_publish(&server, &event);
        if (!strcmp(command, "flood\n"))
            for (int i = 0; i < 100000; i++)
                ipc_publish(&server, &event);
        puts("ok");
    }
    ipc_close(&server);
    return 0;
}
