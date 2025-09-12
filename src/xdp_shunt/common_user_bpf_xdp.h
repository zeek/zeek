/* Common BPF/XDP functions used by userspace side programs */
#ifndef __COMMON_USER_BPF_XDP_H
#define __COMMON_USER_BPF_XDP_H
extern "C" {
struct bpf_object* load_bpf_object_file(const char* filename, int ifindex);
struct xdp_program* load_bpf_and_xdp_attach(struct config* cfg);

const char* action2str(__u32 action);

int check_map_fd_info(const struct bpf_map_info* info, const struct bpf_map_info* exp);

int open_bpf_map_file(const char* pin_dir, const char* mapname, struct bpf_map_info* info);
int do_unload(struct config* cfg);
}
#endif /* __COMMON_USER_BPF_XDP_H */
