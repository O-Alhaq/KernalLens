#ifndef KERNELLENS_EVENT_H
#define KERNELLENS_EVENT_H

/* Fixed-width ABI shared by the BPF program and the C agent. */
struct packet_event {
    __u64 timestamp; /* Monotonic nanoseconds since boot. */
    __u32 ifindex;
    __u32 packet_length;
    __u32 src_ip; /* IPv4 addresses remain in network byte order. */
    __u32 dst_ip;
    __u16 src_port; /* Ports are in host byte order. */
    __u16 dst_port;
    __u8 protocol; /* IPv4 protocol number; zero for non-IPv4. */
    __u8 tcp_flags;
    __u8 ip_version; /* Internal discriminator, zero for unsupported Ethernet. */
    __u8 reserved;
};

_Static_assert(sizeof(struct packet_event) == 32, "packet event ABI mismatch");

struct telemetry_counters {
    __u64 packets;
    __u64 bytes;
    __u64 ipv4;
    __u64 tcp;
    __u64 udp;
    __u64 malformed;
    __u64 ringbuf_dropped;
};

#endif
