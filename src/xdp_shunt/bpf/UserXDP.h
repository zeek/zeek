/* Common BPF/XDP functions used by userspace side programs */
#ifndef __COMMON_USER_BPF_XDP_H
#define __COMMON_USER_BPF_XDP_H

#include <net/if.h>
#include <concepts>
#include <vector>

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

// Helper
template<typename T, typename... U>
concept IsAnyOf = (std::same_as<T, U> || ...);

// Possible key values
template<typename T>
concept SupportedBpfKey = IsAnyOf<T, canonical_tuple, ip_lpm_key>;

struct filter* load_and_attach(int ifindex, xdp_options opts);
void detach_and_destroy_filter(struct filter* skel, int ifindex);

struct bpf_map* get_canonical_id_map(struct filter* skel);
struct bpf_map* get_src_ip_map(struct filter* skel);
struct bpf_map* get_dest_ip_map(struct filter* skel);

template<SupportedBpfKey Key>
int update_map(struct bpf_map* map, Key* key, xdp_action action);

template<SupportedBpfKey Key>
int remove_from_map(struct bpf_map* map, Key* key);
template<SupportedBpfKey Key>
std::vector<Key> get_map(struct bpf_map* map);

#endif /* __COMMON_USER_BPF_XDP_H */
