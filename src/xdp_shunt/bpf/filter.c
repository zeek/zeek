// clang-format off
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
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

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 1024);
    __type(key, struct ip_lpm_key);
    __type(value, __u32);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} dest_ip_map SEC(".maps");

SEC("xdp")
int xdp_filter(struct xdp_md* ctx) {
    void* data_end = (void*)(long)ctx->data_end;
    void* data = (void*)(long)ctx->data;
    struct ethhdr* eth = data;

    if ( data + sizeof(*eth) > data_end )
        return XDP_PASS;

    void* l3_header;
    __u8 l4_protocol;
    struct in6_addr src_ip = {0};
    struct in6_addr dest_ip = {0};
    int is_ipv4 = 0;

    switch ( eth->h_proto ) {
        case __constant_htons(ETH_P_IP): {
            is_ipv4 = 1;
            struct iphdr* iph = data + sizeof(*eth);
            if ( (void*)iph + sizeof(*iph) > data_end )
                return XDP_PASS;

            l3_header = (void*)iph;
            l4_protocol = iph->protocol;

            src_ip.s6_addr[10] = 0xff;
            src_ip.s6_addr[11] = 0xff;
            *((__u32*)&src_ip.s6_addr[12]) = iph->saddr;

            dest_ip.s6_addr[10] = 0xff;
            dest_ip.s6_addr[11] = 0xff;
            *((__u32*)&dest_ip.s6_addr[12]) = iph->daddr;

            break;
        }
        case __constant_htons(ETH_P_IPV6): {
            struct ipv6hdr* ip6h = data + sizeof(*eth);
            if ( (void*)ip6h + sizeof(*ip6h) > data_end )
                return XDP_PASS;

            l3_header = (void*)ip6h;
            l4_protocol = ip6h->nexthdr;
            src_ip = ip6h->saddr;
            dest_ip = ip6h->daddr;
            break;
        }
        default: return XDP_PASS;
    }
    bpf_printk("XDP_DBG: Source IPv6 is %pI6", &src_ip);

    // Print the destination IPv6 address
    bpf_printk("XDP_DBG: Dest IPv6 is %pI6", &dest_ip);

    struct canonical_tuple tuple = {0};
    void* transport_header;

    if ( is_ipv4 )
        transport_header = (void*)((struct iphdr*)l3_header) + sizeof(struct iphdr);
    else
        transport_header = (void*)((struct ipv6hdr*)l3_header) + sizeof(struct ipv6hdr);

    __u16 port_source;
    __u16 port_dest;
    if ( l4_protocol == IPPROTO_TCP ) {
        struct tcphdr* tcph = transport_header;
        if ( (void*)tcph + sizeof(*tcph) > data_end )
            return XDP_PASS;
        port_source = bpf_ntohs(tcph->source); // Host byte order for comparison
        port_dest = bpf_ntohs(tcph->dest);     // Host byte order for comparison
    }
    else if ( l4_protocol == IPPROTO_UDP ) {
        struct udphdr* udph = transport_header;
        if ( (void*)udph + sizeof(*udph) > data_end )
            return XDP_PASS;
        port_source = bpf_ntohs(udph->source);
        port_dest = bpf_ntohs(udph->dest);
    }
    else
        return XDP_PASS;

    tuple.ip1 = src_ip;
    tuple.ip2 = dest_ip;
    // Make sure they're in the correct order
    if ( compare_ips(&src_ip, &dest_ip) < 0 || ((compare_ips(&src_ip, &dest_ip) == 0) && port_source <= port_dest) ) {
        tuple.ip1 = src_ip;
        tuple.ip2 = dest_ip;
        tuple.port1 = bpf_htons(port_source);
        tuple.port2 = bpf_htons(port_dest);
    }
    else {
        tuple.ip1 = dest_ip;
        tuple.ip2 = src_ip;
        tuple.port1 = bpf_htons(port_dest);
        tuple.port2 = bpf_htons(port_source);
    }

    __u32* action = bpf_map_lookup_elem(&filter_map, &tuple);
    if ( action )
        return *action;

    // Check src ip map
    __u32 prefixlen = is_ipv4 ? 32 : 128;
    struct ip_lpm_key src_key = {
        .prefixlen = prefixlen,
        .ip = src_ip,
    };

    action = bpf_map_lookup_elem(&source_ip_map, &src_key);
    if ( action )
        return *action;

    // Check dest ip map
    struct ip_lpm_key dest_key = {
        .prefixlen = prefixlen,
        .ip = dest_ip,
    };

    action = bpf_map_lookup_elem(&dest_ip_map, &dest_key);
    if ( action )
        return *action;

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
