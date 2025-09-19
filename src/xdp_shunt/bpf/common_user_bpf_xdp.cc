#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <xdp/libxdp.h>

#include "bpf/filter.skel.h"

struct filter* open_and_load_bpf() { return filter::open_and_load(); }
int get_bpf_program_fd(struct filter* skel) { return bpf_program__fd(skel->progs.xdp_filter); }
struct bpf_map* get_bpf_filter_map(struct filter* skel) { return skel->maps.filter_map; }
void detach_and_destroy_filter(struct filter* skel, int ifindex) {
    struct bpf_xdp_attach_opts opts = {
        .old_prog_fd = get_bpf_program_fd(skel),
    };
    opts.sz = sizeof(opts);
    bpf_xdp_detach(ifindex, 0, &opts);
    filter::destroy(skel);
}
