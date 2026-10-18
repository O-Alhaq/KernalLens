/* Exercise the production IPC module without requiring BPF privileges. */
#include <stdio.h>
#include <string.h>
#include "ipc.h"

int main(int argc, char **argv)
{
    struct ipc_server server;
    struct packet_event event = {
        .timestamp = 123456789, .ifindex = 2, .packet_length = 86,
    };
    char command[32];

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
