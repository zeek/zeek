// See the file "COPYING" in the main distribution directory for copyright.

// This file is a generated file that was later stripped down to necessary
// parts. Feel free to add necessary components. For future reference, you
// can create a vmlinux.h file with:
//   bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

#ifndef __VMLINUX_H__
#define __VMLINUX_H__

#ifndef BPF_NO_PRESERVE_ACCESS_INDEX
#pragma clang attribute push(__attribute__((preserve_access_index)), apply_to = record)
#endif

#ifndef __ksym
#define __ksym __attribute__((section(".ksyms")))
#endif

#ifndef __weak
#define __weak __attribute__((weak))
#endif

#ifndef __bpf_fastcall
#if __has_attribute(bpf_fastcall)
#define __bpf_fastcall __attribute__((bpf_fastcall))
#else
#define __bpf_fastcall
#endif
#endif

typedef unsigned char __u8;
typedef unsigned short __u16;
typedef unsigned int __u32;
typedef unsigned long long __u64;
typedef __u16 __be16;
typedef __u32 __be32;
typedef short __s16;
typedef int __s32;
typedef __u32 __wsum;
typedef __u16 __sum16;
typedef long long int __s64;

struct ethhdr {
    long : 64;
    int : 32;
    __be16 h_proto;
};

struct in6_addr {
    union {
        __be32 u6_addr32[4];
    } in6_u;
};

struct iphdr {
    __u8 ihl : 4;
    long : 0;
    char : 8;
    __u8 protocol;
    union {
        struct {
            __be32 saddr;
            __be32 daddr;
        };
    };
};

struct ipv6hdr {
    long : 48;
    __u8 nexthdr;
    union {
        struct {
            struct in6_addr saddr;
            struct in6_addr daddr;
        };
    };
};

struct tcphdr {
    __be16 source;
    __be16 dest;
    long : 64;
    int : 32;
};

struct udphdr {
    __be16 source;
    __be16 dest;
    long : 0;
};

struct icmphdr {
    __u8 type;
    __u8 code;
    __sum16 checksum;
    union {
        struct {
            __be16 id;
            __be16 sequence;
        } echo;
        __be32 gateway;
        struct {
            __be16 __unused;
            __be16 mtu;
        } frag;
        __u8 reserved[4];
    } un;
};

struct vlan_hdr {
    __be16 h_vlan_TCI;
    __be16 h_vlan_encapsulated_proto;
};

struct xdp_md {
    __u32 data;
    __u32 data_end;
    long : 64;
    long : 64;
};

enum xdp_action {
    XDP_ABORTED = 0,
    XDP_DROP = 1,
    XDP_PASS = 2,
    XDP_TX = 3,
    XdP_REDIRECT = 4,
};

struct bpf_spin_lock {
    __u32 val;
};

enum bpf_map_type {
    BPF_MAP_TYPE_UNSPEC = 0,
    BPF_MAP_TYPE_HASH = 1,
    BPF_MAP_TYPE_ARRAY = 2,
    BPF_MAP_TYPE_PROG_ARRAY = 3,
    BPF_MAP_TYPE_PERF_EVENT_ARRAY = 4,
    BPF_MAP_TYPE_PERCPU_HASH = 5,
    BPF_MAP_TYPE_PERCPU_ARRAY = 6,
    BPF_MAP_TYPE_STACK_TRACE = 7,
    BPF_MAP_TYPE_CGROUP_ARRAY = 8,
    BPF_MAP_TYPE_LRU_HASH = 9,
    BPF_MAP_TYPE_LRU_PERCPU_HASH = 10,
    BPF_MAP_TYPE_LPM_TRIE = 11,
    BPF_MAP_TYPE_ARRAY_OF_MAPS = 12,
    BPF_MAP_TYPE_HASH_OF_MAPS = 13,
    BPF_MAP_TYPE_DEVMAP = 14,
    BPF_MAP_TYPE_SOCKMAP = 15,
    BPF_MAP_TYPE_CPUMAP = 16,
    BPF_MAP_TYPE_XSKMAP = 17,
    BPF_MAP_TYPE_SOCKHASH = 18,
    BPF_MAP_TYPE_CGROUP_STORAGE_DEPRECATED = 19,
    BPF_MAP_TYPE_CGROUP_STORAGE = 19,
    BPF_MAP_TYPE_REUSEPORT_SOCKARRAY = 20,
    BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE_DEPRECATED = 21,
    BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE = 21,
    BPF_MAP_TYPE_QUEUE = 22,
    BPF_MAP_TYPE_STACK = 23,
    BPF_MAP_TYPE_SK_STORAGE = 24,
    BPF_MAP_TYPE_DEVMAP_HASH = 25,
    BPF_MAP_TYPE_STRUCT_OPS = 26,
    BPF_MAP_TYPE_RINGBUF = 27,
    BPF_MAP_TYPE_INODE_STORAGE = 28,
    BPF_MAP_TYPE_TASK_STORAGE = 29,
    BPF_MAP_TYPE_BLOOM_FILTER = 30,
    BPF_MAP_TYPE_USER_RINGBUF = 31,
    BPF_MAP_TYPE_CGRP_STORAGE = 32,
    BPF_MAP_TYPE_ARENA = 33,
    __MAX_BPF_MAP_TYPE = 34,
};

enum {
    IPPROTO_IP = 0,
    IPPROTO_ICMP = 1,
    IPPROTO_IGMP = 2,
    IPPROTO_IPIP = 4,
    IPPROTO_TCP = 6,
    IPPROTO_EGP = 8,
    IPPROTO_PUP = 12,
    IPPROTO_UDP = 17,
    IPPROTO_IDP = 22,
    IPPROTO_TP = 29,
    IPPROTO_DCCP = 33,
    IPPROTO_IPV6 = 41,
    IPPROTO_RSVP = 46,
    IPPROTO_GRE = 47,
    IPPROTO_ESP = 50,
    IPPROTO_AH = 51,
    IPPROTO_MTP = 92,
    IPPROTO_BEETPH = 94,
    IPPROTO_ENCAP = 98,
    IPPROTO_PIM = 103,
    IPPROTO_COMP = 108,
    IPPROTO_L2TP = 115,
    IPPROTO_SCTP = 132,
    IPPROTO_UDPLITE = 136,
    IPPROTO_MPLS = 137,
    IPPROTO_ETHERNET = 143,
    IPPROTO_AGGFRAG = 144,
    IPPROTO_RAW = 255,
    IPPROTO_SMC = 256,
    IPPROTO_MPTCP = 262,
    IPPROTO_MAX = 263,
};

/* BPF kfuncs */
#ifndef BPF_NO_KFUNC_PROTOTYPES
#endif

#ifndef BPF_NO_PRESERVE_ACCESS_INDEX
#pragma clang attribute pop
#endif

#endif /* __VMLINUX_H__ */
