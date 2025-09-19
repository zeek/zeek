#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <xdp/libxdp.h>

#include "bpf/filter.skel.h"
#include "bpf/filter_common.h"

// TODO: This should probably take a custom opts struct
struct filter* load_and_attach(int ifindex) {
    auto* skel = filter::open_and_load();
    // TODO: How could I get the ifindex without the if_nametoindex stuff?
    auto prog_fd = bpf_program__fd(skel->progs.xdp_filter);
    if ( prog_fd == 0 )
        return nullptr;

    // TODO: Don't hardcode the mode
    int err = bpf_xdp_attach(ifindex, prog_fd, XDP_MODE_SKB, nullptr);
    if ( err )
        return nullptr;

    return skel;
}

struct bpf_map* get_bpf_filter_map(struct filter* skel) { return skel->maps.filter_map; }

int update_filter_map(struct filter* skel, struct five_tuple* tup, xdp_action action) {
    auto err = bpf_map__update_elem(skel->maps.filter_map, tup, sizeof(*tup), &action, sizeof(action), 0);
    // TODO: Better error here if possible
    return err;
}

void detach_and_destroy_filter(struct filter* skel, int ifindex) {
    struct bpf_xdp_attach_opts opts = {
        .old_prog_fd = bpf_program__fd(skel->progs.xdp_filter),
    };
    opts.sz = sizeof(opts);
    bpf_xdp_detach(ifindex, 0, &opts);
    filter::destroy(skel);
}
