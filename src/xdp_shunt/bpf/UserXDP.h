// See the file "COPYING" in the main distribution directory for copyright.

/* Common BPF/XDP functions used by userspace side programs */
#pragma once

#include <net/if.h>
#include <concepts>
#include <map>
#include <optional>
#include <string>

#include "filter_common.h"

struct filter;
struct bpf_map;

namespace zeek::plugin::detail::Zeek_XDP_Shunter {

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
    const char* pin_path;
};

// Helper
template<typename T, typename... U>
concept IsAnyOf = (std::same_as<T, U> || ...);

// Possible key values
template<typename T>
concept SupportedBpfKey = IsAnyOf<T, canonical_tuple, ip_pair_key>;

/**
 * Reuses the maps from an already-existing XDP shunter.
 *
 * This is the preferred way of connecting Zeek to the XDP program so that
 * the brittle Zeek process is not in charge of the health of the XDP
 * program.
 */
std::optional<std::string> reuse_maps(struct filter**, xdp_options opts);

/**
 * Releases the maps from this program. This does NOT unload or
 * otherwise invalidate the XDP program or its maps.
 */
void release_maps(struct filter**);

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

/** Retrieve the canonical ID BPF map of shunted flows. */
struct bpf_map* get_canonical_id_map(struct filter* skel);

/** Retrieve the IP pair BPF map of shunted pairs. */
struct bpf_map* get_ip_pair_map(struct filter* skel);

/** Adds a key to the map. */
template<SupportedBpfKey Key>
std::optional<std::string> update_map(struct bpf_map* map, Key* key);

/** Removes a key to the map. */
template<SupportedBpfKey Key>
std::optional<std::string> remove_from_map(struct bpf_map* map, const Key* key);

/** Retrieves the keys and elements of a given map. */
template<SupportedBpfKey Key>
std::map<Key, struct shunt_val> get_map(struct bpf_map* map);

/** Retrieves the value of a given key in a map, if any. */
template<SupportedBpfKey Key>
std::optional<shunt_val> get_val(struct bpf_map* map, Key* key);

} // namespace zeek::plugin::detail::Zeek_XDP_Shunter
