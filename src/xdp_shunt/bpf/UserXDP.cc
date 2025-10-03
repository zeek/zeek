// clang-format off
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <optional>
#include <string>
#include <unistd.h>
#include <xdp/libxdp.h>

#include "UserXDP.h"

#include "bpf/filter.skel.h"
#include "bpf/filter_common.h"
// clang-format on

std::optional<std::string> load_and_attach(int ifindex, xdp_options opts, struct filter** skel) {
    *skel = filter::open_and_load();
    auto prog_fd = bpf_program__fd((*skel)->progs.xdp_filter);
    if ( prog_fd == 0 )
        return "Could not find BPF program";

    uint32_t flags = 0;
    switch ( opts.mode ) {
        case XDP_MODE_UNSPEC: break;
        case XDP_MODE_NATIVE: flags |= (1U << 2); break;
        case XDP_MODE_SKB: flags |= (1U << 1); break;
        case XDP_MODE_HW: flags |= (1U << 3); break;
    }

    int err = bpf_xdp_attach(ifindex, prog_fd, flags, nullptr);
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
std::optional<std::string> update_map(struct bpf_map* map, Key* key, xdp_action action) {
    auto err = bpf_map_update_elem(bpf_map__fd(map), key, &action, BPF_NOEXIST);
    if ( err ) {
        char err_buf[256];
        libbpf_strerror(err, err_buf, sizeof(err_buf));
        return std::string(err_buf);
    }

    return {};
}

template std::optional<std::string> update_map<canonical_tuple>(struct bpf_map* map, canonical_tuple* key,
                                                                xdp_action action);
template std::optional<std::string> update_map<ip_pair_key>(struct bpf_map* map, ip_pair_key* key, xdp_action action);

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
std::vector<Key> get_map(struct bpf_map* map) {
    std::vector<Key> keys;
    Key key;
    Key next_key;
    Key* prev_key = nullptr;
    while ( bpf_map_get_next_key(bpf_map__fd(map), prev_key, &next_key) == 0 ) {
        keys.push_back(next_key);
        prev_key = &next_key;
    }

    return keys;
}

template std::vector<canonical_tuple> get_map<canonical_tuple>(struct bpf_map* map);
template std::vector<ip_pair_key> get_map<ip_pair_key>(struct bpf_map* map);

void detach_and_destroy_filter(struct filter* skel, int ifindex) {
    unlink(bpf_map__pin_path(skel->maps.filter_map));
    unlink(bpf_map__pin_path(skel->maps.ip_pair_map));
    struct bpf_xdp_attach_opts opts = {
        .old_prog_fd = bpf_program__fd(skel->progs.xdp_filter),
    };
    opts.sz = sizeof(opts);
    bpf_xdp_detach(ifindex, 0, &opts);
    filter::destroy(skel);
}
