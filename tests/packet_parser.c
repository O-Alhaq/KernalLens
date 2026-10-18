/* Run the production parser against packets ending at an inaccessible page. */
#include <arpa/inet.h>
#include <assert.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
#include <bpf/bpf_endian.h>
#include "event.h"
#include "packet_parser.h"

static int check(const unsigned char *packet, size_t length, struct packet_event *event)
{
    size_t page = (size_t)sysconf(_SC_PAGESIZE);
    unsigned char *memory = mmap(NULL, page * 2, PROT_READ | PROT_WRITE,
                                 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    int result;

    assert(memory != MAP_FAILED && length < page);
    assert(mprotect(memory + page, page, PROT_NONE) == 0);
    memcpy(memory + page - length, packet, length);
    memset(event, 0, sizeof(*event));
    result = parse_packet(memory + page - length, memory + page, event);
    assert(munmap(memory, page * 2) == 0);
    return result;
}

static size_t frame(unsigned char *packet, int protocol, int ihl, int transport_length)
{
    size_t length = 14 + ihl + transport_length;
    unsigned char *ip = packet + 14, *transport = ip + ihl;
    unsigned int total = ihl + transport_length;

    memset(packet, 0, 128);
    packet[12] = 8;
    ip[0] = 0x40 | (ihl / 4);
    ip[2] = total >> 8;
    ip[3] = total;
    ip[9] = protocol;
    memcpy(ip + 12, "\xc0\x00\x02\x01\xc0\x00\x02\x02", 8);
    transport[0] = 0xb2;
    transport[1] = 0x6e;
    transport[3] = 80;
    if (protocol == 6) {
        transport[12] = (transport_length / 4) << 4;
        transport[13] = 0x12;
    } else if (protocol == 17) {
        transport[4] = transport_length >> 8;
        transport[5] = transport_length;
    }
    return length;
}

int main(void)
{
    unsigned char packet[128];
    struct packet_event event;
    size_t length;

    length = frame(packet, 6, 20, 20);
    for (size_t size = 0; size < length; size++)
        assert(check(packet, size, &event) == -1);
    assert(check(packet, length, &event) == 1);
    assert(event.ip_version == 4 && event.protocol == 6 && event.tcp_flags == 0x12);
    assert(event.src_port == 45678 && event.dst_port == 80);
    assert(event.src_ip == inet_addr("192.0.2.1") && event.dst_ip == inet_addr("192.0.2.2"));

    length = frame(packet, 17, 20, 8);
    for (size_t size = 0; size < length; size++)
        assert(check(packet, size, &event) == -1);
    assert(check(packet, length, &event) == 1);
    assert(event.protocol == 17 && event.src_port == 45678 && event.dst_port == 80);
    assert(event.tcp_flags == 0);
    packet[14 + 20 + 5] = 7;
    assert(check(packet, length, &event) == -1 && event.src_port == 0);
    packet[14 + 20 + 5] = 9;
    assert(check(packet, length, &event) == -1 && event.dst_port == 0);

    length = frame(packet, 6, 24, 24); /* IP and TCP options. */
    assert(check(packet, length, &event) == 1 && event.src_port == 45678);
    packet[14 + 24 + 12] = 0x40; /* Illegal TCP data offset. */
    assert(check(packet, length, &event) == -1 && event.src_port == 0);
    packet[14 + 24 + 12] = 0xf0; /* TCP options run past IP end. */
    assert(check(packet, length, &event) == -1);

    length = frame(packet, 6, 20, 20);
    packet[14] = 0x44; /* IHL too short. */
    assert(check(packet, length, &event) == -1 && event.ip_version == 0);
    packet[14] = 0x65; /* Incorrect IP version. */
    assert(check(packet, length, &event) == -1);
    packet[14] = 0x45;
    packet[17] = 19; /* Total length shorter than IP header. */
    assert(check(packet, length, &event) == -1);
    packet[17] = 20; /* Ethernet padding must not be read as TCP. */
    assert(check(packet, length, &event) == -1 && event.tcp_flags == 0);

    length = frame(packet, 6, 20, 20);
    packet[20] = 0x20; /* First fragment, more fragments bit. */
    assert(check(packet, length, &event) == 1 && event.src_port == 0 && event.tcp_flags == 0);
    packet[20] = 0;
    packet[21] = 1; /* Later fragment. */
    assert(check(packet, length, &event) == 1 && event.dst_port == 0);
    length = frame(packet, 1, 20, 8);
    assert(check(packet, length, &event) == 1 && event.protocol == 1 && event.src_port == 0);
    packet[12] = 0x86; packet[13] = 0xdd; /* Unsupported IPv6. */
    assert(check(packet, length, &event) == 0 && event.ip_version == 0 && event.src_ip == 0);
    packet[12] = 8; packet[13] = 6; /* ARP. */
    assert(check(packet, length, &event) == 0 && event.protocol == 0);
    puts("PASS: parser truncation, byte order, options, fragments, malformed lengths, defaults");
    return 0;
}
