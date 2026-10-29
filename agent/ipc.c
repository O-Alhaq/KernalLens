#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
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
    server->pending_length = 0;
}

/* Preserve every queued byte, including a partially sent record's suffix.
 * Work per invocation is bounded; the existing main loop retries during idle. */
static void flush_pending(struct ipc_server *server)
{
    for (int attempt = 0; attempt < 16 && server->client >= 0 && server->pending_length; attempt++) {
        ssize_t sent = send(server->client, server->pending, server->pending_length,
                            MSG_DONTWAIT | MSG_NOSIGNAL);
        if (sent > 0) {
            server->pending_length -= (size_t)sent;
            memmove(server->pending, server->pending + sent, server->pending_length);
            continue;
        }
        if (sent < 0 && errno == EINTR)
            continue;
        if (sent < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
            return;
        int error = sent < 0 ? errno : 0;
        fprintf(stderr, "IPC %s: send returned %zd, errno=%d (%s); closing connection.\n",
                error == EPIPE || error == ECONNRESET ? "peer disconnected" : "fatal send error",
                sent, error, error ? strerror(error) : "zero progress");
        disconnect_client(server);
        return;
    }
}

static void send_record(struct ipc_server *server, const char *record, size_t length)
{
    if (server->client < 0)
        return;
    flush_pending(server);
    if (server->client < 0)
        return;
    if (length > sizeof(server->pending) - server->pending_length) {
        if (server->dropped_records++ == 0)
            fprintf(stderr, "IPC send queue full; dropping whole new records, keeping receiver connected.\n");
        return;
    }
    memcpy(server->pending + server->pending_length, record, length);
    server->pending_length += length;
    flush_pending(server);
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
    flush_pending(server);
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

/* Bounded byte escaping also keeps non-UTF-8 Linux filenames valid JSON.
 * Non-ASCII filename bytes are represented individually as \u00XX. */
static void quote_bytes(char *output, const char *input, size_t limit)
{
    static const char hex[] = "0123456789abcdef";

    *output++ = '"';
    for (size_t i = 0; i < limit && input[i]; i++) {
        unsigned char byte = (unsigned char)input[i];

        if (byte == '"' || byte == '\\') {
            *output++ = '\\';
            *output++ = (char)byte;
        } else if (byte < 32 || byte >= 127) {
            *output++ = '\\';
            *output++ = 'u';
            *output++ = '0';
            *output++ = '0';
            *output++ = hex[byte >> 4];
            *output++ = hex[byte & 15];
        } else {
            *output++ = (char)byte;
        }
    }
    *output++ = '"';
    *output = '\0';
}

static int publish_host(struct ipc_server *server, const struct host_event *event)
{
    char record[3072], name[sizeof(event->process_name) * 6 + 3];
    char path[sizeof(event->process_path) * 6 + 3];
    char result[32] = "null", previous_uid[16] = "null", previous_gid[16] = "null";
    const char *category, *type, *syscall = "null";
    int length;

    switch (event->kind) {
    case HOST_PROCESS_EXEC:
        category = "process";
        type = "process_exec";
        if (event->syscall != HOST_NO_SYSCALL)
            return -EINVAL;
        break;
    case HOST_SYSCALL:
    case HOST_PRIVILEGE_CHANGE:
        category = event->kind == HOST_SYSCALL ? "syscall" : "privilege";
        type = event->kind == HOST_SYSCALL ? "syscall_event" : "privilege_change";
        if (event->syscall == HOST_SETUID)
            syscall = "\"setuid\"";
        else if (event->syscall == HOST_SETGID)
            syscall = "\"setgid\"";
        else
            return -EINVAL;
        snprintf(result, sizeof(result), "%" PRId64, (int64_t)event->syscall_return);
        if (event->kind == HOST_PRIVILEGE_CHANGE) {
            snprintf(previous_uid, sizeof(previous_uid), "%u", event->previous_uid);
            snprintf(previous_gid, sizeof(previous_gid), "%u", event->previous_gid);
        }
        break;
    default:
        return -EINVAL;
    }
    quote_bytes(name, event->process_name, sizeof(event->process_name) - 1);
    if (event->process_path[0])
        quote_bytes(path, event->process_path, sizeof(event->process_path) - 1);
    else
        strcpy(path, "null");
    length = snprintf(record, sizeof(record),
        "{\"message_type\":\"event\",\"schema_version\":1,\"event\":{"
        "\"timestamp\":%" PRIu64 ",\"event_category\":\"%s\",\"event_type\":\"%s\","
        "\"pid\":%u,\"ppid\":%u,\"uid\":%u,\"gid\":%u,"
        "\"process_name\":%s,\"process_path\":%s,\"syscall\":%s,"
        "\"syscall_return\":%s,\"previous_uid\":%s,\"previous_gid\":%s}}\n",
        (uint64_t)event->timestamp, category, type, event->pid, event->ppid,
        event->uid, event->gid, name, path, syscall, result, previous_uid, previous_gid);
    if (length < 0 || (size_t)length >= sizeof(record))
        return -EOVERFLOW;
    send_record(server, record, (size_t)length);
    return 0;
}

int ipc_route_event(struct ipc_server *server, const void *data, size_t size)
{
    if (size == sizeof(struct packet_event)) {
        struct packet_event event;

        memcpy(&event, data, sizeof(event));
        ipc_publish(server, &event);
        return 0;
    }
    if (size == sizeof(struct host_event)) {
        struct host_event event;

        memcpy(&event, data, sizeof(event));
        return publish_host(server, &event);
    }
    return -EINVAL;
}

void ipc_close(struct ipc_server *server)
{
    struct stat info;

    if (server->dropped_records)
        fprintf(stderr, "IPC dropped records: %llu\n", server->dropped_records);
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
