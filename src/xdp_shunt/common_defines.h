#ifndef __COMMON_DEFINES_H
#define __COMMON_DEFINES_H

#include <linux/types.h>
#include <net/if.h>
#include <stdbool.h>

enum xdp_attach_mode {
    XDP_MODE_UNSPEC = 0,
    XDP_MODE_NATIVE,
    XDP_MODE_SKB,
    XDP_MODE_HW,
};
struct config {
    enum xdp_attach_mode attach_mode;
    __u32 xdp_flags;
    int ifindex;
    char* ifname;
    char ifname_buf[IF_NAMESIZE];
    int redirect_ifindex;
    char* redirect_ifname;
    char redirect_ifname_buf[IF_NAMESIZE];
    bool do_unload;
    __u32 prog_id;
    bool reuse_maps;
    char pin_dir[512];
    char filename[512];
    char progname[32];
    char src_mac[18];
    char dest_mac[18];
    __u16 xsk_bind_flags;
    int xsk_if_queue;
    bool xsk_poll_mode;
    bool unload_all;
};

/* Defined in common_params.o */
extern int verbose;

/* Exit return codes */
#define EXIT_OK 0   /* == EXIT_SUCCESS (stdlib.h) man exit(3) */
#define EXIT_FAIL 1 /* == EXIT_FAILURE (stdlib.h) man exit(3) */
#define EXIT_FAIL_OPTION 2
#define EXIT_FAIL_XDP 30
#define EXIT_FAIL_BPF 40

#endif /* __COMMON_DEFINES_H */
