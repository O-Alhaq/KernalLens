#include <errno.h>
#include <inttypes.h>
#include <net/if.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "event.h"
#include "ipc.h"
#include "xdp_test.skel.h"

static volatile sig_atomic_t stopping;

static void print_counters(struct xdp_test_bpf *skeleton)
{
    struct telemetry_counters total = {}, *values;
    int cpus = libbpf_num_possible_cpus();
    __u32 key = 0;

    if (cpus <= 0)
        return;
    values = calloc((size_t)cpus, sizeof(*values));
    if (!values)
        return;
    if (bpf_map_lookup_elem(bpf_map__fd(skeleton->maps.counters), &key, values)) {
        fprintf(stderr, "Cannot read telemetry counters: %s\n", strerror(errno));
        free(values);
        return;
    }
    for (int i = 0; i < cpus; i++) {
        total.packets += values[i].packets;
        total.bytes += values[i].bytes;
        total.ipv4 += values[i].ipv4;
        total.tcp += values[i].tcp;
        total.udp += values[i].udp;
        total.malformed += values[i].malformed;
        total.ringbuf_dropped += values[i].ringbuf_dropped;
    }
    fprintf(stderr, "Telemetry: packets=%llu bytes=%llu ipv4=%llu tcp=%llu udp=%llu malformed=%llu ringbuf_dropped=%llu\n",
            total.packets, total.bytes, total.ipv4, total.tcp, total.udp,
            total.malformed, total.ringbuf_dropped);
    free(values);
}

static void stop(int signal_number)
{
    (void)signal_number;
    stopping = 1;
}

static int print_event(void *context, void *data, size_t size)
{
    struct packet_event event;

    if (size != sizeof(event)) {
        fprintf(stderr, "Unexpected event size: %zu\n", size);
        return -EINVAL;
    }
    memcpy(&event, data, sizeof(event));
    ipc_publish(context, &event);
    if (printf("timestamp=%" PRIu64 " ifindex=%" PRIu32
               " packet_length=%" PRIu32 "\n",
               (uint64_t)event.timestamp, (uint32_t)event.ifindex,
               (uint32_t)event.packet_length) < 0)
        return -EIO;
    return 0;
}

int main(int argc, char **argv)
{
    struct xdp_test_bpf *skeleton = NULL;
    struct bpf_link *link = NULL;
    struct ring_buffer *ring = NULL;
    struct sigaction action = { .sa_handler = stop };
    unsigned int ifindex;
    int error = 0;
    struct ipc_server ipc = { .listener = -1, .client = -1 };

    if (argc != 2 && argc != 3) {
        fprintf(stderr, "Usage: %s INTERFACE [SOCKET_PATH]\n", argv[0]);
        return 1;
    }
    ifindex = if_nametoindex(argv[1]);
    if (!ifindex) {
        fprintf(stderr, "Invalid interface %s: %s\n", argv[1], strerror(errno));
        return 1;
    }
    sigemptyset(&action.sa_mask);
    if (sigaction(SIGINT, &action, NULL) || sigaction(SIGTERM, &action, NULL)) {
        perror("sigaction");
        return 1;
    }
    setvbuf(stdout, NULL, _IOLBF, 0);

    skeleton = xdp_test_bpf__open_and_load();
    if (!skeleton) {
        fprintf(stderr, "Cannot load eBPF object: %s\n", strerror(errno));
        return 1;
    }
    if (argc == 3) {
        error = ipc_open(&ipc, argv[2]);
        if (error) {
            fprintf(stderr, "Cannot open IPC socket: %s\n", strerror(-error));
            goto cleanup;
        }
    }
    ring = ring_buffer__new(bpf_map__fd(skeleton->maps.events),
                            print_event, &ipc, NULL);
    if (!ring) {
        error = -errno;
        fprintf(stderr, "Cannot open ring buffer: %s\n", strerror(-error));
        goto cleanup;
    }
    link = bpf_program__attach_xdp(skeleton->progs.xdp_test, (int)ifindex);
    error = (int)libbpf_get_error(link);
    if (error) {
        link = NULL;
        fprintf(stderr, "Cannot attach XDP to %s: %s\n", argv[1], strerror(-error));
        goto cleanup;
    }
    fprintf(stderr, "Attached XDP_PASS to %s (ifindex=%u). Ctrl-C to stop.\n",
            argv[1], ifindex);
    while (!stopping) {
        ipc_poll(&ipc);
        error = ring_buffer__poll(ring, 100);
        if (error == -EINTR) {
            error = 0;
            continue;
        }
        if (error < 0) {
            fprintf(stderr, "Ring buffer poll failed: %s\n", strerror(-error));
            break;
        }
        error = 0;
    }

cleanup:
    ipc_close(&ipc);
    if (link) {
        int detach_error = bpf_link__destroy(link);

        if (detach_error) {
            fprintf(stderr, "XDP detach failed: %s\n", strerror(-detach_error));
            error = detach_error;
        } else {
            fprintf(stderr, "Detached XDP from %s.\n", argv[1]);
        }
        print_counters(skeleton);
    }
    ring_buffer__free(ring);
    xdp_test_bpf__destroy(skeleton);
    return error < 0 ? 1 : 0;
}
