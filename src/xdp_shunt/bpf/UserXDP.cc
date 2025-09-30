// clang-format off
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <unistd.h>
#include <xdp/libxdp.h>

#include "UserXDP.h"

#include "bpf/filter.skel.h"
#include "bpf/filter_common.h"
// clang-format on

struct filter* load_and_attach(int ifindex, xdp_options opts) {
    auto* skel = filter::open_and_load();
    auto prog_fd = bpf_program__fd(skel->progs.xdp_filter);
    if ( prog_fd == 0 )
        return nullptr;

    uint32_t flags = 0;
    switch ( opts.mode ) {
        case XDP_MODE_UNSPEC: break;
        case XDP_MODE_NATIVE: flags |= (1U << 2); break;
        case XDP_MODE_SKB: flags |= (1U << 1); break;
        case XDP_MODE_HW: flags |= (1U << 3); break;
    }

    // TODO: We can get a nicer error here with libbpf_strerror
    int err = bpf_xdp_attach(ifindex, prog_fd, flags, nullptr);
    if ( err )
        return nullptr;

    return skel;
}

struct bpf_map* get_canonical_id_map(struct filter* skel) { return skel->maps.filter_map; }
struct bpf_map* get_src_ip_map(struct filter* skel) { return skel->maps.source_ip_map; }
struct bpf_map* get_dest_ip_map(struct filter* skel) { return skel->maps.dest_ip_map; }

template<SupportedBpfKey Key>
int update_map(struct bpf_map* map, Key* key, xdp_action action) {
    auto err = bpf_map_update_elem(bpf_map__fd(map), key, &action, 0);
    // TODO: Better error here if possible
    return err;
}

template int update_map<canonical_tuple>(struct bpf_map* map, canonical_tuple* key, xdp_action action);
template int update_map<ip_lpm_key>(struct bpf_map* map, ip_lpm_key* key, xdp_action action);

template<SupportedBpfKey Key>
int remove_from_map(struct bpf_map* map, Key* key) {
    auto err = bpf_map_delete_elem(bpf_map__fd(map), key);
    // TODO: Better error here if possible
    return err;
}

template int remove_from_map<canonical_tuple>(struct bpf_map* map, canonical_tuple* key);
template int remove_from_map<ip_lpm_key>(struct bpf_map* map, ip_lpm_key* key);

void detach_and_destroy_filter(struct filter* skel, int ifindex) {
    unlink(bpf_map__pin_path(skel->maps.filter_map));
    unlink(bpf_map__pin_path(skel->maps.source_ip_map));
    unlink(bpf_map__pin_path(skel->maps.dest_ip_map));
    struct bpf_xdp_attach_opts opts = {
        .old_prog_fd = bpf_program__fd(skel->progs.xdp_filter),
    };
    opts.sz = sizeof(opts);
    bpf_xdp_detach(ifindex, 0, &opts);
    filter::destroy(skel);
}
