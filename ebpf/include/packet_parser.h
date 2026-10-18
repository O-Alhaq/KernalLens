#ifndef KERNELLENS_PACKET_PARSER_H
#define KERNELLENS_PACKET_PARSER_H

/* Caller supplies Linux header types and bpf_ntohs. This exact parser is also
 * compiled natively for unprivileged boundary and byte-order tests. Event must
 * be zero-initialized. Returns -1 for malformed, 0 for unsupported, 1 for IPv4.
 */
static __always_inline int parse_packet(void *data, void *data_end,
                                        struct packet_event *event)
{
    struct ethhdr *ethernet = data;
    struct iphdr *ip;
    void *transport, *ip_end;
    unsigned int header_length, total_length;

    if ((void *)(ethernet + 1) > data_end)
        return -1;
    if (bpf_ntohs(ethernet->h_proto) != 0x0800)
        return 0;
    ip = (void *)(ethernet + 1);
    if ((void *)(ip + 1) > data_end)
        return -1;
    if (ip->version != 4 || ip->ihl < 5)
        return -1;
    header_length = ip->ihl * 4;
    total_length = bpf_ntohs(ip->tot_len);
    if (total_length < header_length)
        return -1;
    transport = (void *)ip + header_length;
    ip_end = (void *)ip + total_length;
    if (transport > data_end || ip_end > data_end)
        return -1;
    event->ip_version = 4;
    event->src_ip = ip->saddr;
    event->dst_ip = ip->daddr;
    event->protocol = ip->protocol;

    /* No reassembly: even first fragments retain zero ports/flags. */
    if (bpf_ntohs(ip->frag_off) & 0x3fff)
        return 1;
    if (ip->protocol == 6) {
        struct tcphdr *tcp = transport;
        unsigned int tcp_length;

        if ((void *)(tcp + 1) > data_end || (void *)(tcp + 1) > ip_end)
            return -1;
        tcp_length = tcp->doff * 4;
        if (tcp_length < sizeof(*tcp) ||
            (void *)tcp + tcp_length > data_end ||
            (void *)tcp + tcp_length > ip_end)
            return -1;
        event->src_port = bpf_ntohs(tcp->source);
        event->dst_port = bpf_ntohs(tcp->dest);
        event->tcp_flags = *((unsigned char *)tcp + 13);
    } else if (ip->protocol == 17) {
        struct udphdr *udp = transport;
        unsigned int udp_length;

        if ((void *)(udp + 1) > data_end || (void *)(udp + 1) > ip_end)
            return -1;
        udp_length = bpf_ntohs(udp->len);
        if (udp_length < sizeof(*udp) ||
            (void *)udp + udp_length > data_end ||
            (void *)udp + udp_length > ip_end)
            return -1;
        event->src_port = bpf_ntohs(udp->source);
        event->dst_port = bpf_ntohs(udp->dest);
    }
    return 1;
}

#endif
