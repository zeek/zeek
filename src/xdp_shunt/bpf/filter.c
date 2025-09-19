// clang-format off
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/types.h>
#include <linux/udp.h>
#include <netinet/in.h>
#include <bpf/bpf_helpers.h>
// clang-format on

#include "filter_common.h"

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, struct five_tuple);
    __type(value, __u32);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} filter_map SEC(".maps");

SEC("xdp")
int xdp_filter(struct xdp_md* ctx) {
    void* data_end = (void*)(long)ctx->data_end;
    void* data = (void*)(long)ctx->data;
    struct ethhdr* eth = data;

    if ( data + sizeof(*eth) > data_end ) {
        return XDP_PASS;
    }

    if ( eth->h_proto != __constant_htons(ETH_P_IP) ) {
        return XDP_PASS;
    }

    struct iphdr* iph = data + sizeof(*eth);
    if ( iph + 1 > data_end ) {
        return XDP_PASS;
    }

    struct five_tuple tuple = {0};
    tuple.ip_source = iph->saddr;
    tuple.ip_destination = iph->daddr;
    // tuple.protocol = iph->protocol;

    if ( iph->protocol == IPPROTO_TCP ) {
        struct tcphdr* tcph = (void*)iph + sizeof(*iph);
        if ( (void*)tcph + sizeof(*tcph) > data_end ) {
            return XDP_PASS;
        }
        // tuple.port_source = tcph->source;
        // tuple.port_destination = tcph->dest;
    }
    else if ( iph->protocol == IPPROTO_UDP ) {
        struct udphdr* udph = (void*)iph + sizeof(*iph);
        if ( (void*)udph + sizeof(*udph) > data_end ) {
            return XDP_PASS;
        }
        // tuple.port_source = udph->source;
        // tuple.port_destination = udph->dest;
    }
    else {
        return XDP_PASS;
    }

    __u32* action = bpf_map_lookup_elem(&filter_map, &tuple);
    if ( action )
        return *action;

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
