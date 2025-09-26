#ifndef __FILTER_COMMON_H
#define __FILTER_COMMON_H

#include <linux/types.h>

// Keep Zeek's orig/resp distinction here. The filter program should check
// both directions anyway. The distinction is just for matching ip/port.
struct canonical_tuple {
    __u32 ip1;   // The lower IP
    __u32 ip2;   // The higher IP
    __u16 port1; // The port corresponding with ip1
    __u16 port2; // The port corresponding with ip2
    __u8 protocol;
};

struct ip_lpm_key {
    __u32 prefixlen;
    __u32 ip;
};

#endif /* __FILTER_COMMON_H */
