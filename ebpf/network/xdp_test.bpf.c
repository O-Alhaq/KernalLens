#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include "event.h"

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

SEC("xdp")
int xdp_test(struct xdp_md *ctx)
{
    struct packet_event *event;

    event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event)
        return XDP_PASS;

    event->timestamp = bpf_ktime_get_ns();
    event->ifindex = ctx->ingress_ifindex;
    event->packet_length = ctx->data_end - ctx->data;
    bpf_ringbuf_submit(event, 0);
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
