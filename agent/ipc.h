#ifndef KERNELLENS_IPC_H
#define KERNELLENS_IPC_H

#include <linux/types.h>
#include <sys/types.h>
#include "event.h"

struct ipc_server {
    int listener;
    int client;
    char path[108];
    dev_t device;
    ino_t inode;
};

int ipc_open(struct ipc_server *server, const char *path);
void ipc_poll(struct ipc_server *server);
void ipc_publish(struct ipc_server *server, const struct packet_event *event);
void ipc_close(struct ipc_server *server);

#endif
