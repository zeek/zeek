/* Common BPF/XDP functions used by userspace side programs */
#ifndef __COMMON_USER_BPF_XDP_H
#define __COMMON_USER_BPF_XDP_H

#define LIBBPF_OPTS(TYPE, NAME, ...)                                                                                   \
    struct TYPE NAME = ({                                                                                              \
        memset(&NAME, 0, sizeof(struct TYPE));                                                                         \
        (struct TYPE){.sz = sizeof(struct TYPE), __VA_ARGS__};                                                         \
    })

extern "C" {

struct bpf_object* bpf_object__open_file(const char* path, const struct bpf_object_open_opts* opts);

struct bpf_object* load_bpf_object_file(const char* filename, int ifindex);
struct xdp_program* load_bpf_and_xdp_attach(struct config* cfg);
long libbpf_get_error(const void* ptr);
struct bpf_map* bpf_object__find_map_by_name(const struct bpf_object* obj, const char* name);
int bpf_map__update_elem(const struct bpf_map* map, const void* key, size_t key_sz, const void* value, size_t value_sz,
                         __u64 flags);

const char* action2str(__u32 action);

int check_map_fd_info(const struct bpf_map_info* info, const struct bpf_map_info* exp);

int open_bpf_map_file(const char* pin_dir, const char* mapname, struct bpf_map_info* info);
int do_unload(struct config* cfg);

struct xdp_program_opts {
    size_t sz;
    struct bpf_object* obj;
    struct bpf_object_open_opts* opts;
    const char* prog_name;
    const char* find_filename;
    const char* open_filename;
    const char* pin_path;
    __u32 id;
    int fd;
    size_t : 0;
};

enum xdp_action {
    XDP_ABORTED = 0,
    XDP_DROP,
    XDP_PASS,
    XDP_TX,
    XDP_REDIRECT,
};

long libxdp_get_error(const void* ptr);
int libxdp_strerror(int err, char* buf, size_t size);
struct xdp_program* xdp_program__create(struct xdp_program_opts* opts);
int xdp_program__attach(struct xdp_program* xdp_prog, int ifindex, enum xdp_attach_mode mode, unsigned int flags);
struct bpf_object* xdp_program__bpf_obj(struct xdp_program* xdp_prog);
}
#endif /* __COMMON_USER_BPF_XDP_H */
