#define _GNU_SOURCE
#include "ipc.h"

#include <arpa/inet.h>
#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

static void disconnect_client(struct ipc_server *server)
{
    if (server->client >= 0)
        close(server->client);
    server->client = -1;
}

/* A partial write cannot be followed by another JSON record: disconnect so the
 * receiver can reject the truncated record. Never wait for a slow consumer. */
static void send_record(struct ipc_server *server, const char *record, size_t length)
{
    ssize_t sent;

    if (server->client < 0)
        return;
    do {
        sent = send(server->client, record, length, MSG_DONTWAIT | MSG_NOSIGNAL);
    } while (sent < 0 && errno == EINTR);
    if (sent != (ssize_t)length) {
        fprintf(stderr, "IPC receiver disconnected or too slow; closing connection.\n");
        disconnect_client(server);
    }
}

int ipc_open(struct ipc_server *server, const char *path)
{
    struct sockaddr_un address = { .sun_family = AF_UNIX };
    struct stat info;
    mode_t previous_mask;
    int error;

    memset(server, 0, sizeof(*server));
    server->listener = server->client = -1;
    if (!path[0] || strlen(path) >= sizeof(address.sun_path))
        return -ENAMETOOLONG;
    strcpy(address.sun_path, path);
    server->listener = socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (server->listener < 0)
        return -errno;

    /* Do not remove an existing socket/file, even if it looks stale. */
    previous_mask = umask(0077);
    error = bind(server->listener, (struct sockaddr *)&address, sizeof(address));
    if (error)
        error = -errno;
    umask(previous_mask);
    if (error) {
        goto fail;
    }
    if (lstat(path, &info)) {
        error = -errno;
        goto fail;
    }
    strcpy(server->path, path);
    server->device = info.st_dev;
    server->inode = info.st_ino;
    if (listen(server->listener, 4)) {
        error = -errno;
        goto fail;
    }
    return 0;

fail:
    ipc_close(server);
    return error;
}

void ipc_poll(struct ipc_server *server)
{
    static const char ready[] =
        "{\"message_type\":\"status\",\"schema_version\":1,\"status\":\"ready\"}\n";
    char byte;
    ssize_t received;
    int client;

    if (server->listener < 0)
        return;
    if (server->client >= 0) {
        received = recv(server->client, &byte, 1, MSG_DONTWAIT | MSG_PEEK);
        /* This protocol is one-way; client input is unsupported. */
        if (received >= 0 || (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR))
            disconnect_client(server);
    }
    client = accept4(server->listener, NULL, NULL, SOCK_NONBLOCK | SOCK_CLOEXEC);
    if (client < 0)
        return;
    if (server->client >= 0) {
        close(client);
        return;
    }
    server->client = client;
    send_record(server, ready, sizeof(ready) - 1);
}

void ipc_publish(struct ipc_server *server, const struct packet_event *event)
{
    char record[512];
    char source[INET_ADDRSTRLEN], destination[INET_ADDRSTRLEN], protocol[16];
    int length;

    if (!inet_ntop(AF_INET, &event->src_ip, source, sizeof(source)) ||
        !inet_ntop(AF_INET, &event->dst_ip, destination, sizeof(destination)))
        return;
    if (event->ip_version != 4)
        strcpy(protocol, "OTHER");
    else if (event->protocol == IPPROTO_TCP)
        strcpy(protocol, "TCP");
    else if (event->protocol == IPPROTO_UDP)
        strcpy(protocol, "UDP");
    else if (event->protocol == IPPROTO_ICMP)
        strcpy(protocol, "ICMP");
    else
        snprintf(protocol, sizeof(protocol), "IPPROTO_%u", event->protocol);
    length = snprintf(record, sizeof(record),
        "{\"message_type\":\"event\",\"schema_version\":1,\"event\":{"
        "\"timestamp\":%" PRIu64 ",\"ifindex\":%" PRIu32
        ",\"packet_length\":%" PRIu32
        ",\"src_ip\":\"%s\",\"dst_ip\":\"%s\",\"src_port\":%u,\"dst_port\":%u"
        ",\"protocol\":\"%s\",\"tcp_flags\":%u}}\n",
        (uint64_t)event->timestamp, (uint32_t)event->ifindex,
        (uint32_t)event->packet_length, source, destination,
        event->src_port, event->dst_port, protocol, event->tcp_flags);
    if (length > 0 && (size_t)length < sizeof(record))
        send_record(server, record, (size_t)length);
}

void ipc_close(struct ipc_server *server)
{
    struct stat info;

    disconnect_client(server);
    if (server->listener >= 0)
        close(server->listener);
    server->listener = -1;
    if (server->path[0] && !lstat(server->path, &info) &&
        info.st_dev == server->device && info.st_ino == server->inode &&
        S_ISSOCK(info.st_mode))
        unlink(server->path);
    server->path[0] = '\0';
}
