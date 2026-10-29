#ifndef KERNELLENS_IPC_H
#define KERNELLENS_IPC_H

#include <linux/types.h>
#include <sys/types.h>
#include "event.h"
#include "host_event.h"

#define IPC_QUEUE_BYTES 65536

struct ipc_server {
    int listener;
    int client;
    char path[108];
    dev_t device;
    ino_t inode;
    char pending[IPC_QUEUE_BYTES];
    size_t pending_length;
    unsigned long long dropped_records;
};

int ipc_open(struct ipc_server *server, const char *path);
void ipc_poll(struct ipc_server *server);
void ipc_publish(struct ipc_server *server, const struct packet_event *event);
int ipc_route_event(struct ipc_server *server, const void *data, size_t size);
void ipc_close(struct ipc_server *server);

#endif
