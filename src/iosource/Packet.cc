// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/iosource/Packet.h"

extern "C" {
#include <pcap.h>
#ifdef HAVE_NET_ETHERNET_H
#include <net/ethernet.h>
#elif defined(HAVE_SYS_ETHERNET_H)
#include <sys/ethernet.h>
#elif defined(HAVE_NETINET_IF_ETHER_H)
#include <net/if_arp.h>
#include <netinet/if_ether.h>
#elif defined(HAVE_NET_ETHERTYPES_H)
#include <net/ethertypes.h>
#endif
}

#include "zeek/IP.h"
#include "zeek/Var.h"

#include "zeek/3rdparty/doctest.h"

namespace zeek {

void Packet::Init(int arg_link_type, pkt_timeval* arg_ts, uint32_t arg_caplen, uint32_t arg_len, const u_char* arg_data,
                  bool arg_copy, std::string arg_tag) {
    if ( data && copy )
        delete[] data;

    link_type = arg_link_type;
    ts = *arg_ts;
    cap_len = arg_caplen;
    len = arg_len;
    tag = std::move(arg_tag);

    copy = arg_copy;

    if ( arg_data && arg_copy ) {
        data = new u_char[arg_caplen];
        memcpy(const_cast<u_char*>(data), arg_data, arg_caplen);
    }
    else
        data = arg_data;

    time = ts.tv_sec + static_cast<double>(ts.tv_usec) / 1e6;
    eth_type = 0;

    vlan = 0;
    vlan_pcp = 0;
    vlan_dei = false;

    inner_vlan = 0;
    inner_vlan_pcp = 0;
    inner_vlan_dei = false;

    l3_proto = L3_UNKNOWN;

    is_orig = false;

    l2_checksummed = false;
    l3_checksummed = false;
    l4_checksummed = false;

    l2_src = nullptr;
    l2_dst = nullptr;

    processed = false;

    dump_packet = false;
    dump_size = 0;

    encap.reset();
    ip_hdr.reset();

    proto = -1;
    tunnel_type = BifEnum::Tunnel::NONE;
    gre_version = -1;
    gre_link_type = DLT_RAW;
    session = nullptr;
}

Packet::~Packet() {
    if ( copy )
        delete[] data;
}

RecordValPtr Packet::ToRawPktHdrVal() const {
    static auto raw_pkt_hdr_type = id::find_type<RecordType>("raw_pkt_hdr");
    static auto l2_hdr_type = id::find_type<RecordType>("l2_hdr");
    auto pkt_hdr = make_intrusive<RecordVal>(raw_pkt_hdr_type);
    auto l2_hdr = make_intrusive<RecordVal>(l2_hdr_type);

    bool is_ethernet = link_type == DLT_EN10MB;

    int l3 = BifEnum::L3_UNKNOWN;

    if ( l3_proto == L3_IPV4 )
        l3 = BifEnum::L3_IPV4;

    else if ( l3_proto == L3_IPV6 )
        l3 = BifEnum::L3_IPV6;

    else if ( l3_proto == L3_ARP )
        l3 = BifEnum::L3_ARP;

    // TODO: Get rid of hardcoded l3 protocols.
    // l2_hdr layout:
    //      encap: link_encap;      ##< L2 link encapsulation.
    //      len: count;		##< Total frame length on wire.
    //      cap_len: count;		##< Captured length.
    //      src: string &optional;	##< L2 source (if Ethernet).
    //      dst: string &optional;	##< L2 destination (if Ethernet).
    //      vlan: count &optional;	##< Outermost VLAN tag if any (and Ethernet).
    //      vlan_pcp: count &optional;	##< Outermost VLAN PCP if vlan header is present.
    //      vlan_dei: bool &optional;	##< Outermost VLAN DEI if vlan header is present.
    //      inner_vlan: count &optional;	##< Innermost VLAN tag if any (and Ethernet).
    //      inner_vlan_pcp: count &optional;	##< Innermost VLAN PCP if inner vlan header is present.
    //      inner_vlan_dei: bool &optional;	##< Innermost VLAN DEI if inner vlan header is present.
    //      eth_type: count &optional;	##< Innermost Ethertype (if Ethernet).
    //      proto: layer3_proto;	##< L3 protocol.

    if ( is_ethernet ) {
        // Ethernet header layout is:
        //    dst[6bytes] src[6bytes] ethertype[2bytes]...
        l2_hdr->Assign(0, BifType::Enum::link_encap->GetEnumVal(BifEnum::LINK_ETHERNET));

        // FmtEUI48 needs at least 6 bytes to print out the mac address, plus 6 bytes for
        // skipping over the destination address.
        if ( cap_len >= 12 )
            l2_hdr->Assign(3, FmtEUI48(data + 6)); // src
        else
            l2_hdr->Assign(3, "00:00:00:00:00:00");

        if ( cap_len >= 6 )
            l2_hdr->Assign(4, FmtEUI48(data)); // dst
        else
            l2_hdr->Assign(4, "00:00:00:00:00:00");

        if ( vlan ) {
            l2_hdr->Assign(5, vlan);
            l2_hdr->Assign(6, vlan_pcp);
            l2_hdr->Assign(7, vlan_dei);
        }

        if ( inner_vlan ) {
            l2_hdr->Assign(8, inner_vlan);
            l2_hdr->Assign(9, inner_vlan_pcp);
            l2_hdr->Assign(10, inner_vlan_dei);
        }

        l2_hdr->Assign(11, eth_type);

        if ( eth_type == ETHERTYPE_ARP || eth_type == ETHERTYPE_REVARP )
            // We also identify ARP for L3 over ethernet
            l3 = BifEnum::L3_ARP;
    }
    else
        l2_hdr->Assign(0, BifType::Enum::link_encap->GetEnumVal(BifEnum::LINK_UNKNOWN));

    l2_hdr->Assign(1, len);
    l2_hdr->Assign(2, cap_len);

    l2_hdr->Assign(12, BifType::Enum::layer3_proto->GetEnumVal(l3));

    pkt_hdr->Assign(0, std::move(l2_hdr));

    // The cap_len >= ip_hdr->TotalLen() and Reassembled() checks ensure that
    // ToPktHdrVal() doesn't access out of bounds memory. For reassembled datagrams,
    // cap_len ends up less than the reassembled packets total length.
    if ( ip_hdr && (cap_len >= ip_hdr->TotalLen() || ip_hdr->Reassembled()) &&
         (l3_proto == L3_IPV4 || l3_proto == L3_IPV6) )
        // Packet analysis will have stored the IP header in the packet, so we can use
        // that to build the output.
        return ip_hdr->ToPktHdrVal(std::move(pkt_hdr), 1);
    else
        return pkt_hdr;
}

RecordValPtr Packet::ToVal(const Packet* p) {
    static auto pcap_packet = zeek::id::find_type<zeek::RecordType>("pcap_packet");
    auto val = zeek::make_intrusive<zeek::RecordVal>(pcap_packet);

    if ( p ) {
        val->Assign(0, static_cast<uint32_t>(p->ts.tv_sec));
        val->Assign(1, static_cast<uint32_t>(p->ts.tv_usec));
        val->Assign(2, p->cap_len);
        val->Assign(3, p->len);
        val->Assign(4, zeek::make_intrusive<zeek::StringVal>(p->cap_len, reinterpret_cast<const char*>(p->data)));
        val->Assign(5, zeek::BifType::Enum::link_encap->GetEnumVal(p->link_type));
    }
    else {
        val->Assign(0, 0);
        val->Assign(1, 0);
        val->Assign(2, 0);
        val->Assign(3, 0);
        val->Assign(4, zeek::val_mgr->EmptyString());
        val->Assign(5, zeek::BifType::Enum::link_encap->GetEnumVal(BifEnum::LINK_UNKNOWN));
    }

    return val;
}

ValPtr Packet::FmtEUI48(const u_char* mac) const {
    char buf[20];
    snprintf(buf, sizeof buf, "%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return make_intrusive<StringVal>(buf);
}

} // namespace zeek

TEST_SUITE("Packet") {
    TEST_CASE("Packet::Init fields") {
        // This test verifies that Packet::Init() resets unaffected fields back
        // to constructor defaults.

        zeek::Packet p;

        // Adjust the fields to non-default values:

        u_char tmp = 1;

        p.eth_type = 1;
        p.vlan = 1;
        p.vlan_pcp = 1;
        p.vlan_dei = true;
        p.inner_vlan = 1;
        p.inner_vlan_pcp = 1;
        p.inner_vlan_dei = true;
        p.l3_proto = zeek::L3_ARP;
        p.is_orig = true;
        p.l2_checksummed = true;
        p.l3_checksummed = true;
        p.l4_checksummed = true;
        p.l2_src = &tmp;
        p.l2_dst = &tmp;
        p.processed = true;
        p.dump_packet = true;
        p.dump_size = 1;
        p.encap = std::make_shared<zeek::EncapsulationStack>();
        p.ip_hdr = std::make_shared<zeek::IP_Hdr>(nullptr, false);
        p.proto = 1;
        p.tunnel_type = zeek::BifEnum::Tunnel::IP;
        p.gre_version = 1;
        p.gre_link_type = DLT_EN10MB;
        p.session = reinterpret_cast<zeek::session::Session*>(1);

        // Re-initialize the packet and verify that these fields now match
        // constructor defaults.

        pkt_timeval ts = {2, 2};
        const u_char tmp2[2] = {2, 2};
        p.Init(DLT_RAW, &ts, 2, 2, tmp2, false, "bar");

        zeek::Packet p_clean;

        CHECK(p.eth_type == p_clean.eth_type);
        CHECK(p.vlan == p_clean.vlan);
        CHECK(p.vlan_pcp == p_clean.vlan_pcp);
        CHECK(p.vlan_dei == p_clean.vlan_dei);
        CHECK(p.inner_vlan == p_clean.inner_vlan);
        CHECK(p.inner_vlan_pcp == p_clean.inner_vlan_pcp);
        CHECK(p.inner_vlan_dei == p_clean.inner_vlan_dei);
        CHECK(p.l3_proto == p_clean.l3_proto);
        CHECK(p.is_orig == p_clean.is_orig);
        CHECK(p.l2_checksummed == p_clean.l2_checksummed);
        CHECK(p.l3_checksummed == p_clean.l3_checksummed);
        CHECK(p.l4_checksummed == p_clean.l4_checksummed);
        CHECK(p.l2_src == p_clean.l2_src);
        CHECK(p.l2_dst == p_clean.l2_dst);
        CHECK(p.processed == p_clean.processed);
        CHECK(p.dump_packet == p_clean.dump_packet);
        CHECK(p.dump_size == p_clean.dump_size);
        CHECK(p.encap.get() == p_clean.encap.get());
        CHECK(p.ip_hdr.get() == p_clean.ip_hdr.get());
        CHECK(p.proto == p_clean.proto);
        CHECK(p.tunnel_type == p_clean.tunnel_type);
        CHECK(p.gre_version == p_clean.gre_version);
        CHECK(p.gre_link_type == p_clean.gre_link_type);
        CHECK(p.session == p_clean.session);
    }
}
