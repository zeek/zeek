// clang-format off
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/types.h>
#include <linux/udp.h>
#include <netinet/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
// clang-format on

#include "filter_common.h"

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, struct canonical_tuple);
    __type(value, __u32);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} filter_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 1024);
    __type(key, struct ip_lpm_key);
    __type(value, __u32);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} source_ip_map SEC(".maps");

SEC("xdp")
int xdp_filter(struct xdp_md* ctx) {
    void* data_end = (void*)(long)ctx->data_end;
    void* data = (void*)(long)ctx->data;
    struct ethhdr* eth = data;

    if ( data + sizeof(*eth) > data_end )
        return XDP_PASS;

    if ( eth->h_proto != __constant_htons(ETH_P_IP) )
        return XDP_PASS;

    struct iphdr* iph = data + sizeof(*eth);
    if ( (void*)iph + sizeof(*iph) > data_end )
        return XDP_PASS;

    __u16 port_source = 0;
    __u16 port_dest = 0;
    if ( iph->protocol == IPPROTO_TCP ) {
        struct tcphdr* tcph = (void*)iph + sizeof(*iph);
        if ( (void*)tcph + sizeof(*tcph) > data_end )
            return XDP_PASS;

        port_source = bpf_ntohs(tcph->source);
        port_dest = bpf_ntohs(tcph->dest);
    }
    else if ( iph->protocol == IPPROTO_UDP ) {
        struct udphdr* udph = (void*)iph + sizeof(*iph);
        if ( (void*)udph + sizeof(*udph) > data_end )
            return XDP_PASS;

        port_source = bpf_ntohs(udph->source);
        port_dest = bpf_ntohs(udph->dest);
    }
    else
        return XDP_PASS;

    struct canonical_tuple tuple;
    tuple.protocol = iph->protocol;

    // Make sure they're in the correct order
    if ( iph->saddr < iph->daddr || (iph->saddr == iph->daddr && port_source <= port_dest) ) {
        tuple.ip1 = iph->saddr;
        tuple.ip2 = iph->daddr;
        tuple.port1 = port_source;
        tuple.port2 = port_dest;
    }
    else {
        tuple.ip1 = iph->daddr;
        tuple.ip2 = iph->saddr;
        tuple.port1 = port_dest;
        tuple.port2 = port_source;
    }

    __u32* action = bpf_map_lookup_elem(&filter_map, &tuple);
    if ( action )
        return *action;

    // Check src ip map
    struct ip_lpm_key src_key = {
        .prefixlen = 32,
        .ip = iph->saddr,
    };

    action = bpf_map_lookup_elem(&source_ip_map, &src_key);
    if ( action )
        return *action;

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
