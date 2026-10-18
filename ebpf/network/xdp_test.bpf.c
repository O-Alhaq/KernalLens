#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "event.h"
#include "packet_parser.h"

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct telemetry_counters);
} counters SEC(".maps");

SEC("xdp")
int xdp_test(struct xdp_md *ctx)
{
    struct packet_event *event;
    struct packet_event parsed = {};
    __u32 key = 0;
    struct telemetry_counters *stats = bpf_map_lookup_elem(&counters, &key);
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    int result = parse_packet(data, data_end, &parsed);

    parsed.timestamp = bpf_ktime_get_ns();
    parsed.ifindex = ctx->ingress_ifindex;
    parsed.packet_length = data_end - data;
    if (stats) {
        stats->packets++;
        stats->bytes += parsed.packet_length;
        if (parsed.ip_version == 4)
            stats->ipv4++;
        if (parsed.protocol == 6)
            stats->tcp++;
        if (parsed.protocol == 17)
            stats->udp++;
        if (result < 0)
            stats->malformed++;
    }

    event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event) {
        if (stats)
            stats->ringbuf_dropped++;
        return XDP_PASS;
    }

    *event = parsed;
    bpf_ringbuf_submit(event, 0);
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
