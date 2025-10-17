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

#ifndef BPF_MAX_SIZE
#define BPF_MAX_SIZE 65535
#endif

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, BPF_MAX_SIZE);
    __type(key, struct canonical_tuple);
    __type(value, struct shunt_val);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} filter_map SEC(".maps");

// For both canonical IDs and IP pairs
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, BPF_MAX_SIZE);
} filter_rb SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, BPF_MAX_SIZE);
    __type(key, struct ip_pair_key);
    __type(value, struct shunt_val);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} ip_pair_map SEC(".maps");

// Returns the new combined number of fin/rst
static __always_inline __u32 update_value(struct shunt_val* val, struct xdp_md* ctx, int from_ip1, __u16 fin,
                                          __u16 rst) {
    __u64 new_ts = bpf_ktime_get_ns(); // Call before getting lock

    bpf_spin_lock(&val->lock);

    // TODO: Consider swapping to PER_CPU
    void* data_end = (void*)(long)ctx->data_end;
    void* data = (void*)(long)ctx->data;
    __u64 bytes = data_end - data;
    if ( from_ip1 ) {
        val->packets_from_1++;
        val->bytes_from_1 += bytes;
    }
    else {
        val->packets_from_2++;
        val->bytes_from_2 += bytes;
    }

    // Only update the timestamp if the new one is more recent
    if ( new_ts > val->timestamp )
        val->timestamp = new_ts;

    val->fin += fin;
    val->rst += rst;

    __u32 result = val->fin + val->rst;

    bpf_spin_unlock(&val->lock);

    return result;
}

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

    struct canonical_tuple tuple = {0};
    void* transport_header;

    if ( is_ipv4 ) {
        struct iphdr* iph = l3_header;
        int ip_hdr_len = iph->ihl * 4;
        transport_header = (void*)((unsigned char*)iph + ip_hdr_len);
    }
    else
        // TODO: Walk through IPV6 extension headers?
        transport_header = (void*)((struct ipv6hdr*)l3_header) + sizeof(struct ipv6hdr);

    __u16 port_source;
    __u16 port_dest;
    __u16 fin = 0;
    __u16 rst = 0;
    if ( l4_protocol == IPPROTO_TCP ) {
        struct tcphdr* tcph = transport_header;
        if ( (void*)tcph + sizeof(*tcph) > data_end )
            return XDP_PASS;
        port_source = bpf_ntohs(tcph->source);
        port_dest = bpf_ntohs(tcph->dest);
        fin = tcph->fin != 0;
        rst = tcph->rst != 0;
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

    tuple.protocol = l4_protocol;
    tuple.ip1 = src_ip;
    tuple.ip2 = dest_ip;
    int from_ip1 = 1;
    // Make sure they're in the correct order
    if ( compare_ips(&src_ip, &dest_ip) < 0 || ((compare_ips(&src_ip, &dest_ip) == 0) && port_source <= port_dest) ) {
        tuple.ip1 = src_ip;
        tuple.ip2 = dest_ip;
        tuple.port1 = port_source;
        tuple.port2 = port_dest;
    }
    else {
        from_ip1 = 0;
        tuple.ip1 = dest_ip;
        tuple.ip2 = src_ip;
        tuple.port1 = port_dest;
        tuple.port2 = port_source;
    }

    struct shunt_val* val = bpf_map_lookup_elem(&filter_map, &tuple);
    if ( val ) {
        if ( update_value(val, ctx, from_ip1, fin, rst) == 1 ) {
            struct canonical_tuple* rb_data =
                (struct canonical_tuple*)(bpf_ringbuf_reserve(&filter_rb, sizeof(struct canonical_tuple), 0));
            if ( rb_data ) {
                *rb_data = tuple;
                bpf_ringbuf_submit(rb_data, 0);
            }
        }

        return XDP_DROP;
    }

    // Check IP pairs
    struct ip_pair_key pair = {
        .ip1 = tuple.ip1,
        .ip2 = tuple.ip2,
    };

    val = bpf_map_lookup_elem(&ip_pair_map, &pair);
    if ( val ) {
        if ( update_value(val, ctx, from_ip1, fin, rst) == 1 ) {
            struct ip_pair_key* rb_data =
                (struct ip_pair_key*)(bpf_ringbuf_reserve(&filter_rb, sizeof(struct ip_pair_key), 0));
            if ( rb_data ) {
                *rb_data = pair;
                bpf_ringbuf_submit(rb_data, 0);
            }
        }
        return XDP_DROP;
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
