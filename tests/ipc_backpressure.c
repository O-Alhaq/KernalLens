#define _GNU_SOURCE
/* Deterministic syscall injection: force partial sends and transient/fatal errors. */
#include <assert.h>
#include <errno.h>
#include <string.h>
#include <sys/socket.h>
static int mode;
static char output[1024];
static size_t used;
static ssize_t fake_send(int fd, const void *data, size_t length, int flags)
{
    (void)fd; (void)flags;
    if (mode == 1) { errno = EAGAIN; return -1; }
    if (mode == 2) { errno = EPIPE; return -1; }
    if (mode == 3) { errno = ETIMEDOUT; return -1; }
    size_t count = length > 3 ? 3 : length;
    memcpy(output + used, data, count);
    used += count;
    mode = 1; /* pause immediately after a partial send */
    return (ssize_t)count;
}
#define send fake_send
#include "../agent/ipc.c"
#undef send
int main(void)
{
    struct ipc_server server = {.listener = -1, .client = -1};
    int pair[2];
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == 0);
    server.client = pair[0];
    send_record(&server, "{\"a\":1}\n", 8);
    assert(used == 3 && server.pending_length == 5 && server.client >= 0);
    send_record(&server, "{\"b\":2}\n", 8);
    assert(server.pending_length == 13);
    while (server.pending_length) { mode = 0; flush_pending(&server); }
    assert(used == 16 && !memcmp(output, "{\"a\":1}\n{\"b\":2}\n", 16));
    mode = 1;
    memset(server.pending, 'x', sizeof(server.pending));
    server.pending_length = sizeof(server.pending);
    send_record(&server, "{}\n", 3);
    assert(server.pending_length == IPC_QUEUE_BYTES && server.dropped_records == 1);
    assert(server.client >= 0);
    mode = 2;
    flush_pending(&server);
    assert(server.client == -1 && server.pending_length == 0);
    close(pair[1]);
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == 0);
    server.client = pair[0];
    mode = 3;
    send_record(&server, "{}\n", 3);
    assert(server.client == -1);
    close(pair[1]);
    return 0;
}
