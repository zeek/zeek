#ifndef __FILTER_COMMON_H
#define __FILTER_COMMON_H

#include <linux/types.h>
#include <netinet/in.h>

struct canonical_tuple {
    struct in6_addr ip1; // The lower IP
    struct in6_addr ip2; // The higher IP
    __u16 port1;         // The port corresponding with ip1
    __u16 port2;         // The port corresponding with ip2
    __u8 protocol;
};

struct ip_pair_key {
    struct in6_addr ip1;
    struct in6_addr ip2;
};

static __always_inline int compare_ips(struct in6_addr* ip1, struct in6_addr* ip2) {
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
