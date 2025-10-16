#ifndef __FILTER_COMMON_H
#define __FILTER_COMMON_H

#include <linux/types.h>
#include <netinet/in.h>

struct canonical_tuple {
    struct in6_addr ip1; // The lower IP
    struct in6_addr ip2; // The higher IP
    __u16 port1;         // The port corresponding with ip1
    __u16 port2;         // The port corresponding with ip2
    __u32 protocol;      // The protocol for this connection.
                         // Due to padding, this should be 32 bytes.
                         // If it's not, keys may say they're missing,
                         // when indeed they are present. :(
};

struct ip_pair_key {
    struct in6_addr ip1;
    struct in6_addr ip2;
};

// Statistics for shunted flows
struct shunt_val {
// Since BPF headers conflict in user code with the pcap ones, we need
// to use __u32 in user code for the lock.
#ifdef __bpf__
    struct bpf_spin_lock lock;
#else
    __u32 lock_pad;
#endif

    __u64 packets_from_1; // packets from IP 1 as the source
    __u64 packets_from_2; // packets from IP 2 as the source
    __u64 bytes_from_1;   // bytes from IP 1 as the source
    __u64 bytes_from_2;   // bytes from IP 2 as the source
    __u64 timestamp;      // monotonic NS since boot from last packet
    __u16 fin;            // number of TCP fin packets seen
    __u16 rst;            // number of TCP rst packets seen
};

static __always_inline int compare_ips(const struct in6_addr* ip1, const struct in6_addr* ip2) {
    const __u64* a64 = (const __u64*)ip1;
    const __u64* b64 = (const __u64*)ip2;

    if ( a64[0] > b64[0] )
        return 1;
    if ( a64[0] < b64[0] )
        return -1;

    if ( a64[1] > b64[1] )
        return 1;
    if ( a64[1] < b64[1] )
        return -1;

    return 0;
}

#endif /* __FILTER_COMMON_H */
