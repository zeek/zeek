// clang-format off
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <filesystem>
#include <optional>
#include <string>
#include <unistd.h>
#include <xdp/libxdp.h>
#include <zeek/util.h>

#include "UserXDP.h"

#include "bpf/filter.skel.h"
#include "bpf/filter_common.h"
// clang-format on

bool operator<(const canonical_tuple& lhs, const canonical_tuple& rhs) {
    auto ip1_cmp = compare_ips(&lhs.ip1, &rhs.ip1);
    if ( ip1_cmp != 0 )
        return ip1_cmp < 0;

    auto ip2_cmp = compare_ips(&lhs.ip2, &rhs.ip2);
    if ( ip2_cmp != 0 )
        return ip2_cmp < 0;

    if ( lhs.port1 != rhs.port1 )
        return lhs.port1 < rhs.port1;

    if ( lhs.port2 != rhs.port2 )
        return lhs.port2 < rhs.port2;

    return lhs.protocol < rhs.protocol;
}

bool operator<(const ip_pair_key& lhs, const ip_pair_key& rhs) {
    int ip1_cmp = compare_ips(&lhs.ip1, &rhs.ip1);
    if ( ip1_cmp != 0 )
        return ip1_cmp < 0;

    int ip2_cmp = compare_ips(&lhs.ip2, &rhs.ip2);
    return ip2_cmp < 0;
}

uint32_t flags(xdp_options opts) {
    uint32_t flags = 0;
    switch ( opts.mode ) {
        case XDP_MODE_UNSPEC: break;
        case XDP_MODE_NATIVE: flags |= (1U << 2); break;
        case XDP_MODE_SKB: flags |= (1U << 1); break;
        case XDP_MODE_HW: flags |= (1U << 3); break;
    }

    return flags;
}

std::optional<std::string> reconnect(struct filter** skel, xdp_options opts) {
    // Exit if the map dir doesn't exist
    if ( ! std::filesystem::exists(opts.pin_path) )
        // TODO: Also don't hardcode here.
        return "Pin path /sys/fs/bpf/zeek does not exist";

    struct bpf_object_open_opts open_opts = {
        .sz = sizeof(struct bpf_object_open_opts),
        .pin_root_path = opts.pin_path,
    };
    *skel = filter::open(&open_opts);

    bpf_map__set_max_entries(get_canonical_id_map(*skel), opts.conn_id_map_max_size);
    bpf_map__set_max_entries(get_ip_pair_map(*skel), opts.ip_pair_map_max_size);

    if ( ! *skel )
        return "Failed to open BPF skeleton";

    if ( auto err = filter::load(*skel) ) {
        filter::destroy(*skel);
        *skel = nullptr;
        return "Failed to load BPF skeleton";
    }

    return {};
}

void disconnect(struct filter** skel) {
    filter::destroy(*skel);
    *skel = nullptr;
}

std::optional<std::string> load_and_attach(int ifindex, xdp_options opts, struct filter** skel) {
    auto prog_fd = bpf_obj_get(zeek::util::fmt("%s/%s", opts.pin_path, "xdp_filter"));

    // Already exists
    if ( prog_fd >= 0 ) {
        bpf_xdp_attach(ifindex, prog_fd, flags(opts), nullptr);
        return {};
    }

    struct bpf_object_open_opts open_opts = {
        .sz = sizeof(struct bpf_object_open_opts),
        .pin_root_path = opts.pin_path,
    };
    *skel = filter::open(&open_opts);

    // This must be 1 or greater.
    bpf_map__set_max_entries(get_canonical_id_map(*skel), opts.conn_id_map_max_size);
    bpf_map__set_max_entries(get_ip_pair_map(*skel), opts.ip_pair_map_max_size);

    (*skel)->rodata->include_vlan = opts.include_vlan;

    filter::load(*skel);
    prog_fd = bpf_program__fd((*skel)->progs.xdp_filter);
    if ( prog_fd < 0 )
        return "Could not find BPF program";

    auto err = bpf_xdp_attach(ifindex, prog_fd, flags(opts), nullptr);
    if ( err ) {
        char err_buf[256];
        libbpf_strerror(err, err_buf, sizeof(err_buf));
        return std::string(err_buf);
    }

    return {};
}

struct bpf_map* get_canonical_id_map(struct filter* skel) { return skel->maps.filter_map; }
struct bpf_map* get_ip_pair_map(struct filter* skel) { return skel->maps.ip_pair_map; }

template<SupportedBpfKey Key>
std::optional<std::string> update_map(struct bpf_map* map, Key* key) {
    auto val = shunt_val{0};
    auto err = bpf_map_update_elem(bpf_map__fd(map), key, &val, BPF_ANY);
    if ( err ) {
        char err_buf[256];
        libbpf_strerror(err, err_buf, sizeof(err_buf));
        return std::string(err_buf);
    }

    return {};
}

template std::optional<std::string> update_map<canonical_tuple>(struct bpf_map* map, canonical_tuple* key);
template std::optional<std::string> update_map<ip_pair_key>(struct bpf_map* map, ip_pair_key* key);

template<SupportedBpfKey Key>
std::optional<std::string> remove_from_map(struct bpf_map* map, Key* key) {
    auto err = bpf_map_delete_elem(bpf_map__fd(map), key);
    if ( err ) {
        char err_buf[256];
        libbpf_strerror(err, err_buf, sizeof(err_buf));
        return std::string(err_buf);
    }

    return {};
}

template std::optional<std::string> remove_from_map<canonical_tuple>(struct bpf_map* map, canonical_tuple* key);
template std::optional<std::string> remove_from_map<ip_pair_key>(struct bpf_map* map, ip_pair_key* key);

template<SupportedBpfKey Key>
std::map<Key, struct shunt_val> get_map(struct bpf_map* map) {
    std::map<Key, struct shunt_val> found_map;
    Key next_key;
    Key* prev_key = nullptr;
    while ( bpf_map_get_next_key(bpf_map__fd(map), prev_key, &next_key) == 0 ) {
        shunt_val value;
        if ( bpf_map_lookup_elem(bpf_map__fd(map), &next_key, &value) != 0 )
            // TODO: what would I do?
            return {};

        found_map[next_key] = value;
        prev_key = &next_key;
    }

    return found_map;
}

template std::map<canonical_tuple, struct shunt_val> get_map<canonical_tuple>(struct bpf_map* map);
template std::map<ip_pair_key, struct shunt_val> get_map<ip_pair_key>(struct bpf_map* map);

template<SupportedBpfKey Key>
std::optional<shunt_val> get_val(struct bpf_map* map, Key* key) {
    shunt_val value;

    if ( bpf_map_lookup_elem(bpf_map__fd(map), key, &value) != 0 )
        return std::nullopt;

    return value;
}

template std::optional<shunt_val> get_val<canonical_tuple>(struct bpf_map* map, canonical_tuple* key);
template std::optional<shunt_val> get_val<ip_pair_key>(struct bpf_map* map, ip_pair_key* key);

void detach_and_destroy_filter(struct filter* skel, int ifindex, xdp_options attached_opts) {
    unlink(bpf_map__pin_path(skel->maps.filter_map));
    unlink(bpf_map__pin_path(skel->maps.ip_pair_map));
    struct bpf_xdp_attach_opts opts = {
        .old_prog_fd = bpf_program__fd(skel->progs.xdp_filter),
    };
    opts.sz = sizeof(opts);

    bpf_xdp_detach(ifindex, flags(attached_opts), &opts);
    filter::destroy(skel);
}
