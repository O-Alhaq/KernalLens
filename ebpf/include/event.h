#ifndef KERNELLENS_EVENT_H
#define KERNELLENS_EVENT_H

/* Fixed-width ABI shared by the BPF program and the C agent. */
struct packet_event {
    __u64 timestamp; /* Monotonic nanoseconds since boot. */
    __u32 ifindex;
    __u32 packet_length;
};

_Static_assert(sizeof(struct packet_event) == 16, "packet event ABI mismatch");

#endif
