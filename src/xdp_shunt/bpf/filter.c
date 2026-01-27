// clang-format off
#include "vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
// clang-format on

#include "filter_common.h"

#ifndef BPF_MAX_SIZE
#define BPF_MAX_SIZE 65535
#endif

#ifndef VLAN_MAX_DEPTH
#define VLAN_MAX_DEPTH 8
#endif

#define ETH_P_8021Q 0x8100
#define ETH_P_8021AD 0x88A8
#define ETH_P_IP 0x0800
#define ETH_P_IPV6 0x86DD

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, BPF_MAX_SIZE);
    __type(key, struct canonical_tuple);
    __type(value, struct shunt_val);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} filter_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, BPF_MAX_SIZE);
    __type(key, struct ip_pair_key);
    __type(value, struct shunt_val);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} ip_pair_map SEC(".maps");

// Whether we should include the VLANs in the keys or 0 them out.
// VLANs will still get parsed regardless.
volatile const uint8_t include_vlan = 0;

struct hdr_cursor {
    void* pos;
};

static __always_inline int proto_is_vlan(__u16 h_proto) {
    return h_proto == bpf_htons(ETH_P_8021Q) || h_proto == bpf_htons(ETH_P_8021AD);
}

// Mostly copied from xdp-tutorial:
// https://github.com/xdp-project/xdp-tutorial/blob/main/packet-solutions/xdp_vlan01_kern.c
static __always_inline int parse_ethhdr(struct hdr_cursor* nh, void* data_end, struct ethhdr** ethhdr,
                                        __u16* outer_vlan, __u16* inner_vlan) {
    struct ethhdr* eth = nh->pos;
    int hdrsize = sizeof(*eth);
    __u16 h_proto;

    if ( nh->pos + hdrsize > data_end )
        return -1;

    nh->pos += hdrsize;
    *ethhdr = eth;
    struct vlan_hdr* vlh = nh->pos;
    h_proto = eth->h_proto;

/* Use loop unrolling to avoid the verifier restriction on loops;
 * support up to VLAN_MAX_DEPTH layers of VLAN encapsulation.
 */
#pragma unroll
    for ( int i = 0; i < VLAN_MAX_DEPTH; i++ ) {
        if ( ! proto_is_vlan(h_proto) )
            break;

        if ( (void*)vlh + sizeof(struct vlan_hdr) > data_end )
            break;


        __u16 tci_host = bpf_ntohs(vlh->h_vlan_TCI);
        // Only set inner vlan if outer is 0. This mimics Zeek's behavior.
        if ( *outer_vlan == 0 )
            *outer_vlan = tci_host & 0x0FFF;
        else
            *inner_vlan = tci_host & 0x0FFF;

        h_proto = vlh->h_vlan_encapsulated_proto;
        vlh++;
    }

    nh->pos = vlh;
    return h_proto; /* network-byte-order */
}

// Returns the new combined number of fin/rst
static __always_inline void update_value(struct shunt_val* val, struct xdp_md* ctx, int from_ip1) {
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

    bpf_spin_unlock(&val->lock);
}

SEC("xdp")
int xdp_filter(struct xdp_md* ctx) {
    void* data_end = (void*)(long)ctx->data_end;
    void* data = (void*)(long)ctx->data;

    struct hdr_cursor nh;
    nh.pos = data;

    struct ethhdr* eth;
    __u16 outer_vlan = 0;
    __u16 inner_vlan = 0;
    int nh_type = parse_ethhdr(&nh, data_end, &eth, &outer_vlan, &inner_vlan);
    if ( nh_type < 0 )
        return XDP_PASS;

    void* l3_header;
    __u8 l4_protocol;
    struct in6_addr src_ip = {0};
    struct in6_addr dest_ip = {0};
    int is_ipv4 = 0;

    switch ( nh_type ) {
        case bpf_htons(ETH_P_IP): {
            is_ipv4 = 1;
            struct iphdr* iph = nh.pos;
            if ( (void*)iph + sizeof(*iph) > data_end )
                return XDP_PASS;

            l3_header = (void*)iph;
            l4_protocol = iph->protocol;

            src_ip.in6_u.u6_addr32[0] = 0;
            src_ip.in6_u.u6_addr32[1] = 0;
            src_ip.in6_u.u6_addr32[2] = bpf_htonl(0x0000FFFF);
            src_ip.in6_u.u6_addr32[3] = iph->saddr;

            dest_ip.in6_u.u6_addr32[0] = 0;
            dest_ip.in6_u.u6_addr32[1] = 0;
            dest_ip.in6_u.u6_addr32[2] = bpf_htonl(0x0000FFFF);
            dest_ip.in6_u.u6_addr32[3] = iph->daddr;

            break;
        }
        case bpf_htons(ETH_P_IPV6): {
            struct ipv6hdr* ip6h = nh.pos;
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

    struct canonical_tuple tuple;
    __builtin_memset(&tuple, 0, sizeof(tuple));

    if ( include_vlan ) {
        tuple.outer_vlan_id = outer_vlan;
        tuple.inner_vlan_id = inner_vlan;
    }

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
    char is_control_packet = 0;
    if ( l4_protocol == IPPROTO_TCP ) {
        struct tcphdr* tcph = transport_header;
        if ( (void*)tcph + sizeof(*tcph) > data_end )
            return XDP_PASS;

        // Forward all TCP control packets
        is_control_packet = tcph->fin || tcph->rst || tcph->syn || tcph->ack;

        port_source = bpf_ntohs(tcph->source);
        port_dest = bpf_ntohs(tcph->dest);
    }
    else if ( l4_protocol == IPPROTO_UDP ) {
        struct udphdr* udph = transport_header;
        if ( (void*)udph + sizeof(*udph) > data_end )
            return XDP_PASS;

        port_source = bpf_ntohs(udph->source);
        port_dest = bpf_ntohs(udph->dest);
    }
    else if ( l4_protocol == IPPROTO_ICMP ) {
        struct icmphdr* icmph = transport_header;
        if ( (void*)icmph + sizeof(*icmph) > data_end )
            return XDP_PASS;

        port_source = 0;
        port_dest = 0;
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
        update_value(val, ctx, from_ip1);
        if ( is_control_packet )
            return XDP_PASS;
        return XDP_DROP;
    }

    // Check IP pairs
    struct ip_pair_key pair;
    __builtin_memset(&pair, 0, sizeof(pair));

    pair.ip1 = tuple.ip1;
    pair.ip2 = tuple.ip2;

    if ( include_vlan ) {
        pair.outer_vlan_id = outer_vlan;
        pair.inner_vlan_id = inner_vlan;
    }

    val = bpf_map_lookup_elem(&ip_pair_map, &pair);
    if ( val ) {
        update_value(val, ctx, from_ip1);
        if ( is_control_packet )
            return XDP_PASS;
        return XDP_DROP;
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
