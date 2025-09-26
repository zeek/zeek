/* Common BPF/XDP functions used by userspace side programs */
#ifndef __COMMON_USER_BPF_XDP_H
#define __COMMON_USER_BPF_XDP_H

#include <net/if.h>

#include "bpf/filter_common.h"

struct filter;

// TODO: Prevent these from conflicting better
#ifndef __LIBXDP_LIBXDP_H
enum xdp_action {
    XDP_ABORTED = 0,
    XDP_DROP,
    XDP_PASS,
    XDP_TX,
    XDP_REDIRECT,
};

enum xdp_attach_mode {
    XDP_MODE_UNSPEC = 0,
    XDP_MODE_NATIVE,
    XDP_MODE_SKB,
    XDP_MODE_HW,
};
#endif

struct xdp_options {
    xdp_attach_mode mode;
};

struct filter* load_and_attach(int ifindex, xdp_options opts);
int update_filter_map(struct filter* skel, canonical_tuple* tup, xdp_action action);
int remove_from_filter_map(struct filter* skel, canonical_tuple* tup);
void detach_and_destroy_filter(struct filter* skel, int ifindex);

#endif /* __COMMON_USER_BPF_XDP_H */
