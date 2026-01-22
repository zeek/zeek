/* Common BPF/XDP functions used by userspace side programs */
#ifndef __COMMON_USER_BPF_XDP_H
#define __COMMON_USER_BPF_XDP_H

#include <net/if.h>
#include <concepts>
#include <map>
#include <optional>
#include <string>

#include "bpf/filter_common.h"

struct filter;

#ifndef __LIBXDP_LIBXDP_H
enum xdp_action { // NOLINT(performance-enum-size)
    XDP_ABORTED = 0,
    XDP_DROP,
    XDP_PASS,
    XDP_TX,
    XDP_REDIRECT,
};

enum xdp_attach_mode { // NOLINT(performance-enum-size)
    XDP_MODE_UNSPEC = 0,
    XDP_MODE_NATIVE,
    XDP_MODE_SKB,
    XDP_MODE_HW,
};

struct ring_buffer;
#endif

struct xdp_options {
    xdp_attach_mode mode;
    __u32 conn_id_map_max_size;
    __u32 ip_pair_map_max_size;
    bool include_vlan;
};

// Helper
template<typename T, typename... U>
concept IsAnyOf = (std::same_as<T, U> || ...);

// Possible key values
template<typename T>
concept SupportedBpfKey = IsAnyOf<T, canonical_tuple, ip_pair_key>;

/**
 * Loads and attaches to the XDP program. This will simply grab the file
 * descriptor if it's already there, otherwise it will load the XDP program
 * itself.
 *
 * Normally, the Zeek cluster should start the XDP program before, then
 * each process simply gets the FD.
 */
std::optional<std::string> load_and_attach(int ifindex, xdp_options opts, struct filter**);

/**
 * Detaches the XDP program and unpins the maps. Note that this should only
 * ever be done with a corresponding load_and_attach call. Otherwise, it
 * should not be up to the Zeek process itself to load and unload the XDP
 * program.
 */
void detach_and_destroy_filter(struct filter* skel, int ifindex, xdp_options opts);

struct bpf_map* get_canonical_id_map(struct filter* skel);
struct bpf_map* get_ip_pair_map(struct filter* skel);

template<SupportedBpfKey Key>
std::optional<std::string> update_map(struct bpf_map* map, Key* key);

template<SupportedBpfKey Key>
std::optional<std::string> remove_from_map(struct bpf_map* map, Key* key);
template<SupportedBpfKey Key>
std::map<Key, struct shunt_val> get_map(struct bpf_map* map);
template<SupportedBpfKey Key>
std::optional<shunt_val> get_val(struct bpf_map* map, Key* key);

using ring_buffer_sample_fn = int (*)(void* ctx, void* data, size_t size);
struct ring_buffer* make_shunt_fin_buffer(struct filter* skel, ring_buffer_sample_fn cb);
// Thin wrapper around ring_buffer__free
void free_ring_buffer(ring_buffer* rb);
// Thin wrapper around ring_buffer__poll
void poll_shunt_fin(ring_buffer* rb, int timeout_ms);

#endif /* __COMMON_USER_BPF_XDP_H */
