#ifndef __FILTER_COMMON_H
#define __FILTER_COMMON_H

#include <linux/types.h>

// Keep Zeek's orig/resp distinction here. The filter program should check
// both directions anyway. The distinction is just for matching ip/port.
struct five_tuple {
    __u32 ip_orig;
    __u32 ip_resp;
    __u16 port_orig;
    __u16 port_resp;
    __u8 protocol;
};

#endif /* __FILTER_COMMON_H */
