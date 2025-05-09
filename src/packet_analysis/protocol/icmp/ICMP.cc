// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/packet_analysis/protocol/icmp/ICMP.h"

#include <netinet/icmp6.h>

#include "zeek/Conn.h"
#include "zeek/Desc.h"
#include "zeek/Reporter.h"
#include "zeek/RunState.h"
#include "zeek/Val.h"
#include "zeek/ZeekString.h"
#include "zeek/analyzer/Manager.h"
#include "zeek/packet_analysis/protocol/icmp/ICMPSessionAdapter.h"
#include "zeek/packet_analysis/protocol/icmp/events.bif.h"
#include "zeek/session/Manager.h"

enum ICMP_EndpointState {
    ICMP_INACTIVE, // no packet seen
    ICMP_ACTIVE,   // packets seen
};

using namespace zeek::packet_analysis::ICMP;
using namespace zeek::packet_analysis::IP;

ICMPAnalyzer::ICMPAnalyzer() : IPBasedAnalyzer("ICMP", TRANSPORT_ICMP, ICMP_PORT_MASK, false) {}

SessionAdapter* ICMPAnalyzer::MakeSessionAdapter(Connection* conn) {
    auto* root = new ICMPSessionAdapter(conn);
    root->SetParent(this);
    conn->SetInactivityTimeout(zeek::detail::icmp_inactivity_timeout);

    return root;
}

bool ICMPAnalyzer::BuildConnTuple(size_t len, const uint8_t* data, Packet* packet, ConnTuple& tuple) {
    if ( ! CheckHeaderTrunc(ICMP_MINLEN, len, packet) )
        return false;

    tuple.src_addr = packet->ip_hdr->SrcAddr();
    tuple.dst_addr = packet->ip_hdr->DstAddr();
    tuple.proto = packet->proto;

    const struct icmp* icmpp = (const struct icmp*)data;
    tuple.src_port = htons(icmpp->icmp_type);

    if ( packet->proto == IPPROTO_ICMP )
        tuple.dst_port = htons(ICMP4_counterpart(icmpp->icmp_type, icmpp->icmp_code, tuple.is_one_way));
    else if ( packet->proto == IPPROTO_ICMPV6 )
        tuple.dst_port = htons(ICMP6_counterpart(icmpp->icmp_type, icmpp->icmp_code, tuple.is_one_way));
    else
        reporter->InternalError("Reached ICMP packet analyzer with unknown packet protocol %x", packet->proto);

    return true;
}

void ICMPAnalyzer::DeliverPacket(Connection* c, double t, bool is_orig, int remaining, Packet* pkt) {
    auto* adapter = static_cast<ICMPSessionAdapter*>(c->GetSessionAdapter());

    const u_char* data = pkt->ip_hdr->Payload();
    int len = pkt->ip_hdr->PayloadLen();
    // If segment offloading or similar is enabled, the payload len will return 0.
    // Thus, let's ignore that case.
    if ( len == 0 )
        len = remaining;

    if ( packet_contents && len > 0 )
        adapter->PacketContents(data + 8, std::min(len, remaining) - 8);

    const struct icmp* icmpp = (const struct icmp*)data;
    const std::shared_ptr<IP_Hdr>& ip = pkt->ip_hdr;

    if ( ! zeek::detail::ignore_checksums && ! GetIgnoreChecksumsNets()->Contains(ip->IPHeaderSrcAddr()) &&
         remaining >= len ) {
        int chksum = 0;

        switch ( ip->NextProto() ) {
            case IPPROTO_ICMP: chksum = icmp_checksum(icmpp, len); break;

            case IPPROTO_ICMPV6: chksum = icmp6_checksum(icmpp, ip.get(), len); break;

            default: reporter->Error("unexpected IP proto in ICMP analyzer: %d", ip->NextProto()); return;
        }

        if ( chksum != 0xffff ) {
            adapter->Weird("bad_ICMP_checksum");
            return;
        }
    }

    c->SetLastTime(run_state::current_timestamp);
    adapter->InitEndpointMatcher(ip.get(), len, is_orig);

    // Move past common portion of ICMP header. BuildConnTuple() verified that
    // the header is fully present.
    data += 8;
    remaining -= 8;
    len -= 8;

    // The ICMP session adapter only uses len to signal endpoint activity, so
    // caplen vs len does not matter.
    adapter->UpdateLength(is_orig, len);

    if ( ip->NextProto() == IPPROTO_ICMP )
        NextICMP4(run_state::current_timestamp, icmpp, len, remaining, data, ip.get(), adapter);
    else if ( ip->NextProto() == IPPROTO_ICMPV6 )
        NextICMP6(run_state::current_timestamp, icmpp, len, remaining, data, ip.get(), adapter);
    else {
        reporter->Error("expected ICMP as IP packet's protocol, got %d", ip->NextProto());
        return;
    }

    // Store the session in the packet in case we get an encapsulation here. We need it for
    // handling those properly.
    pkt->session = c;

    ForwardPacket(std::min(len, remaining), data, pkt);

    if ( remaining >= len )
        adapter->ForwardPacket(len, data, is_orig, -1, ip.get(), remaining);

    adapter->MatchEndpoint(data, std::min(len, remaining), is_orig);
}

void ICMPAnalyzer::NextICMP4(double t, const struct icmp* icmpp, int len, int caplen, const u_char*& data,
                             const IP_Hdr* ip_hdr, ICMPSessionAdapter* adapter) {
    switch ( icmpp->icmp_type ) {
        case ICMP_ECHO:
        case ICMP_ECHOREPLY: Echo(t, icmpp, len, caplen, data, ip_hdr, adapter); break;

        case ICMP_UNREACH:
        case ICMP_TIMXCEED: Context4(t, icmpp, len, caplen, data, ip_hdr, adapter); break;

        default: ICMP_Sent(icmpp, len, caplen, 0, data, ip_hdr, adapter); break;
    }
}

void ICMPAnalyzer::NextICMP6(double t, const struct icmp* icmpp, int len, int caplen, const u_char*& data,
                             const IP_Hdr* ip_hdr, ICMPSessionAdapter* adapter) {
    switch ( icmpp->icmp_type ) {
        // Echo types.
        case ICMP6_ECHO_REQUEST:
        case ICMP6_ECHO_REPLY: Echo(t, icmpp, len, caplen, data, ip_hdr, adapter); break;

        // Error messages all have the same structure for their context,
        // and are handled by the same function.
        case ICMP6_PARAM_PROB:
        case ICMP6_TIME_EXCEEDED:
        case ICMP6_PACKET_TOO_BIG:
        case ICMP6_DST_UNREACH: Context6(t, icmpp, len, caplen, data, ip_hdr, adapter); break;

        // Router related messages.
        case ND_REDIRECT: Redirect(t, icmpp, len, caplen, data, ip_hdr, adapter); break;
        case ND_ROUTER_ADVERT: RouterAdvert(t, icmpp, len, caplen, data, ip_hdr, adapter); break;
        case ND_NEIGHBOR_ADVERT: NeighborAdvert(t, icmpp, len, caplen, data, ip_hdr, adapter); break;
        case ND_NEIGHBOR_SOLICIT: NeighborSolicit(t, icmpp, len, caplen, data, ip_hdr, adapter); break;
        case ND_ROUTER_SOLICIT: RouterSolicit(t, icmpp, len, caplen, data, ip_hdr, adapter); break;
        case ICMP6_ROUTER_RENUMBERING: ICMP_Sent(icmpp, len, caplen, 1, data, ip_hdr, adapter); break;

#if 0
		// Currently not specifically implemented.
		case MLD_LISTENER_QUERY:
		case MLD_LISTENER_REPORT:
		case MLD_LISTENER_REDUCTION:
#endif
        default:
            // Error messages (i.e., ICMPv6 type < 128) all have
            // the same structure for their context, and are
            // handled by the same function.
            if ( icmpp->icmp_type < 128 )
                Context6(t, icmpp, len, caplen, data, ip_hdr, adapter);
            else
                ICMP_Sent(icmpp, len, caplen, 1, data, ip_hdr, adapter);
            break;
    }
}

void ICMPAnalyzer::ICMP_Sent(const struct icmp* icmpp, int len, int caplen, int icmpv6, const u_char* data,
                             const IP_Hdr* ip_hdr, ICMPSessionAdapter* adapter) {
    if ( icmp_sent )
        adapter->EnqueueConnEvent(icmp_sent, adapter->ConnVal(), BuildInfo(icmpp, len, icmpv6, ip_hdr));

    if ( icmp_sent_payload ) {
        String* payload = new String(data, std::min(len, caplen), false);

        adapter->EnqueueConnEvent(icmp_sent_payload, adapter->ConnVal(), BuildInfo(icmpp, len, icmpv6, ip_hdr),
                                  make_intrusive<StringVal>(payload));
    }
}

zeek::RecordValPtr ICMPAnalyzer::BuildInfo(const struct icmp* icmpp, int len, bool icmpv6, const IP_Hdr* ip_hdr) {
    static auto icmp_info = id::find_type<RecordType>("icmp_info");
    auto rval = make_intrusive<zeek::RecordVal>(icmp_info);
    rval->Assign(0, val_mgr->Bool(icmpv6));
    rval->Assign(1, val_mgr->Count(icmpp->icmp_type));
    rval->Assign(2, val_mgr->Count(icmpp->icmp_code));
    rval->Assign(3, val_mgr->Count(len));
    rval->Assign(4, val_mgr->Count(ip_hdr->TTL()));
    return rval;
}

TransportProto ICMPAnalyzer::GetContextProtocol(const IP_Hdr* ip_hdr, uint32_t* src_port, uint32_t* dst_port) {
    const u_char* transport_hdr;
    uint32_t ip_hdr_len = ip_hdr->HdrLen();
    bool ip4 = ip_hdr->IP4_Hdr();

    if ( ip4 )
        transport_hdr = ((u_char*)ip_hdr->IP4_Hdr() + ip_hdr_len);
    else
        transport_hdr = ((u_char*)ip_hdr->IP6_Hdr() + ip_hdr_len);

    TransportProto proto;

    switch ( ip_hdr->NextProto() ) {
        case 1: proto = TRANSPORT_ICMP; break;
        case 6: proto = TRANSPORT_TCP; break;
        case 17: proto = TRANSPORT_UDP; break;
        case 58: proto = TRANSPORT_ICMP; break;
        default: proto = TRANSPORT_UNKNOWN; break;
    }

    switch ( proto ) {
        case TRANSPORT_ICMP: {
            const struct icmp* icmpp = (const struct icmp*)transport_hdr;
            bool is_one_way; // dummy
            *src_port = ntohs(icmpp->icmp_type);

            if ( ip4 )
                *dst_port = ntohs(ICMP4_counterpart(icmpp->icmp_type, icmpp->icmp_code, is_one_way));
            else
                *dst_port = ntohs(ICMP6_counterpart(icmpp->icmp_type, icmpp->icmp_code, is_one_way));

            break;
        }

        case TRANSPORT_TCP: {
            const struct tcphdr* tp = (const struct tcphdr*)transport_hdr;
            *src_port = ntohs(tp->th_sport);
            *dst_port = ntohs(tp->th_dport);
            break;
        }

        case TRANSPORT_UDP: {
            const struct udphdr* up = (const struct udphdr*)transport_hdr;
            *src_port = ntohs(up->uh_sport);
            *dst_port = ntohs(up->uh_dport);
            break;
        }

        default: *src_port = *dst_port = ntohs(0); break;
    }

    return proto;
}

zeek::RecordValPtr ICMPAnalyzer::ExtractICMP4Context(int len, const u_char*& data) {
    uint32_t ip_len, frag_offset;
    bool bad_hdr_len = false;
    bool bad_checksum = false;
    TransportProto proto = TRANSPORT_UNKNOWN;
    int DF, MF;
    IPAddr src_addr, dst_addr;
    uint32_t src_port, dst_port;

    if ( len < (int)sizeof(struct ip) ) {
        // We don't have an entire IP header.
        bad_hdr_len = true;
        bad_checksum = false;
        ip_len = frag_offset = 0;
        DF = MF = 0;
        src_port = dst_port = 0;
    }

    else {
        const IP_Hdr ip_hdr_data((const struct ip*)data, false);
        const IP_Hdr* ip_hdr = &ip_hdr_data;
        uint32_t ip_hdr_len = ip_hdr->HdrLen();
        bad_hdr_len = (ip_hdr_len > static_cast<uint32_t>(len));

        if ( ! bad_hdr_len )
            bad_checksum = ! run_state::current_pkt->l4_checksummed &&
                           (zeek::detail::in_cksum(reinterpret_cast<const uint8_t*>(ip_hdr->IP4_Hdr()),
                                                   static_cast<int>(ip_hdr_len)) != 0xffff);
        else
            bad_checksum = false;

        ip_len = ip_hdr->TotalLen();

        src_addr = ip_hdr->SrcAddr();
        dst_addr = ip_hdr->DstAddr();

        DF = ip_hdr->DF();
        MF = ip_hdr->MF();
        frag_offset = ip_hdr->FragOffset();

        if ( uint32_t(len) >= ip_hdr_len + 4 )
            proto = GetContextProtocol(ip_hdr, &src_port, &dst_port);
        else {
            // 4 above is the magic number meaning that both
            // port numbers are included in the ICMP.
            src_port = dst_port = 0;
            bad_hdr_len = true;
        }
    }

    static auto icmp_context = id::find_type<RecordType>("icmp_context");
    auto iprec = make_intrusive<zeek::RecordVal>(icmp_context);
    auto id_val = make_intrusive<zeek::RecordVal>(id::conn_id);

    id_val->Assign(0, make_intrusive<AddrVal>(src_addr));
    id_val->Assign(1, val_mgr->Port(src_port, proto));
    id_val->Assign(2, make_intrusive<AddrVal>(dst_addr));
    id_val->Assign(3, val_mgr->Port(dst_port, proto));
    id_val->Assign(4, IPPROTO_ICMP);

    iprec->Assign(0, std::move(id_val));
    iprec->Assign(1, val_mgr->Count(ip_len));
    iprec->Assign(2, val_mgr->Count(proto));
    iprec->Assign(3, val_mgr->Count(frag_offset));
    iprec->Assign(4, val_mgr->Bool(bad_hdr_len));
    iprec->Assign(5, val_mgr->Bool(bad_checksum));
    iprec->Assign(6, val_mgr->Bool(MF));
    iprec->Assign(7, val_mgr->Bool(DF));

    return iprec;
}

zeek::RecordValPtr ICMPAnalyzer::ExtractICMP6Context(int len, const u_char*& data) {
    int DF = 0, MF = 0, bad_hdr_len = 0;
    TransportProto proto = TRANSPORT_UNKNOWN;

    IPAddr src_addr;
    IPAddr dst_addr;
    uint32_t ip_len, frag_offset = 0;
    uint32_t src_port, dst_port;

    if ( len < (int)sizeof(struct ip6_hdr) ) {
        bad_hdr_len = 1;
        ip_len = 0;
        src_port = dst_port = 0;
    }
    else {
        const IP_Hdr ip_hdr_data((const struct ip6_hdr*)data, false, len);
        const IP_Hdr* ip_hdr = &ip_hdr_data;

        ip_len = ip_hdr->TotalLen();
        src_addr = ip_hdr->SrcAddr();
        dst_addr = ip_hdr->DstAddr();
        frag_offset = ip_hdr->FragOffset();
        MF = ip_hdr->MF();
        DF = ip_hdr->DF();

        if ( uint32_t(len) >= uint32_t(ip_hdr->HdrLen() + 4) )
            proto = GetContextProtocol(ip_hdr, &src_port, &dst_port);
        else {
            // 4 above is the magic number meaning that both
            // port numbers are included in the ICMP.
            src_port = dst_port = 0;
            bad_hdr_len = 1;
        }
    }

    static auto icmp_context = id::find_type<RecordType>("icmp_context");
    auto iprec = make_intrusive<zeek::RecordVal>(icmp_context);
    auto id_val = make_intrusive<zeek::RecordVal>(id::conn_id);

    id_val->Assign(0, make_intrusive<AddrVal>(src_addr));
    id_val->Assign(1, val_mgr->Port(src_port, proto));
    id_val->Assign(2, make_intrusive<AddrVal>(dst_addr));
    id_val->Assign(3, val_mgr->Port(dst_port, proto));
    id_val->Assign(4, IPPROTO_ICMPV6);

    iprec->Assign(0, std::move(id_val));
    iprec->Assign(1, val_mgr->Count(ip_len));
    iprec->Assign(2, val_mgr->Count(proto));
    iprec->Assign(3, val_mgr->Count(frag_offset));
    iprec->Assign(4, val_mgr->Bool(bad_hdr_len));
    // bad_checksum is always false since IPv6 layer doesn't have a checksum.
    iprec->Assign(5, val_mgr->False());
    iprec->Assign(6, val_mgr->Bool(MF));
    iprec->Assign(7, val_mgr->Bool(DF));

    return iprec;
}

void ICMPAnalyzer::Echo(double t, const struct icmp* icmpp, int len, int caplen, const u_char*& data,
                        const IP_Hdr* ip_hdr, ICMPSessionAdapter* adapter) {
    // For handling all Echo related ICMP messages
    EventHandlerPtr f = nullptr;

    if ( ip_hdr->NextProto() == IPPROTO_ICMPV6 )
        f = (icmpp->icmp_type == ICMP6_ECHO_REQUEST) ? icmp_echo_request : icmp_echo_reply;
    else
        f = (icmpp->icmp_type == ICMP_ECHO) ? icmp_echo_request : icmp_echo_reply;

    if ( ! f )
        return;

    int iid = ntohs(icmpp->icmp_hun.ih_idseq.icd_id);
    int iseq = ntohs(icmpp->icmp_hun.ih_idseq.icd_seq);

    String* payload = new String(data, caplen, false);

    adapter->EnqueueConnEvent(f, adapter->ConnVal(), BuildInfo(icmpp, len, ip_hdr->NextProto() != IPPROTO_ICMP, ip_hdr),
                              val_mgr->Count(iid), val_mgr->Count(iseq), make_intrusive<StringVal>(payload));
}

void ICMPAnalyzer::RouterAdvert(double t, const struct icmp* icmpp, int len, int caplen, const u_char*& data,
                                const IP_Hdr* ip_hdr, ICMPSessionAdapter* adapter) {
    EventHandlerPtr f = icmp_router_advertisement;

    if ( ! f )
        return;

    uint32_t reachable = 0, retrans = 0;

    if ( caplen >= (int)sizeof(reachable) )
        memcpy(&reachable, data, sizeof(reachable));

    if ( caplen >= (int)sizeof(reachable) + (int)sizeof(retrans) )
        memcpy(&retrans, data + sizeof(reachable), sizeof(retrans));

    int opt_offset = sizeof(reachable) + sizeof(retrans);

    adapter->EnqueueConnEvent(f, adapter->ConnVal(), BuildInfo(icmpp, len, true, ip_hdr),
                              val_mgr->Count(icmpp->icmp_num_addrs),         // Cur Hop Limit
                              val_mgr->Bool(icmpp->icmp_wpa & 0x80),         // Managed
                              val_mgr->Bool(icmpp->icmp_wpa & 0x40),         // Other
                              val_mgr->Bool(icmpp->icmp_wpa & 0x20),         // Home Agent
                              val_mgr->Count((icmpp->icmp_wpa & 0x18) >> 3), // Pref
                              val_mgr->Bool(icmpp->icmp_wpa & 0x04),         // Proxy
                              val_mgr->Count(icmpp->icmp_wpa & 0x02),        // Reserved
                              make_intrusive<IntervalVal>((double)ntohs(icmpp->icmp_lifetime), Seconds),
                              make_intrusive<IntervalVal>((double)ntohl(reachable), Milliseconds),
                              make_intrusive<IntervalVal>((double)ntohl(retrans), Milliseconds),
                              BuildNDOptionsVal(caplen - opt_offset, data + opt_offset, adapter));
}

void ICMPAnalyzer::NeighborAdvert(double t, const struct icmp* icmpp, int len, int caplen, const u_char*& data,
                                  const IP_Hdr* ip_hdr, ICMPSessionAdapter* adapter) {
    EventHandlerPtr f = icmp_neighbor_advertisement;

    if ( ! f )
        return;

    IPAddr tgtaddr;

    if ( caplen >= (int)sizeof(in6_addr) )
        tgtaddr = IPAddr(*((const in6_addr*)data));

    int opt_offset = sizeof(in6_addr);

    adapter->EnqueueConnEvent(f, adapter->ConnVal(), BuildInfo(icmpp, len, true, ip_hdr),
                              val_mgr->Bool(icmpp->icmp_num_addrs & 0x80), // Router
                              val_mgr->Bool(icmpp->icmp_num_addrs & 0x40), // Solicited
                              val_mgr->Bool(icmpp->icmp_num_addrs & 0x20), // Override
                              make_intrusive<AddrVal>(tgtaddr),
                              BuildNDOptionsVal(caplen - opt_offset, data + opt_offset, adapter));
}

void ICMPAnalyzer::NeighborSolicit(double t, const struct icmp* icmpp, int len, int caplen, const u_char*& data,
                                   const IP_Hdr* ip_hdr, ICMPSessionAdapter* adapter) {
    EventHandlerPtr f = icmp_neighbor_solicitation;

    if ( ! f )
        return;

    IPAddr tgtaddr;

    if ( caplen >= (int)sizeof(in6_addr) )
        tgtaddr = IPAddr(*((const in6_addr*)data));

    int opt_offset = sizeof(in6_addr);

    adapter->EnqueueConnEvent(f, adapter->ConnVal(), BuildInfo(icmpp, len, true, ip_hdr),
                              make_intrusive<AddrVal>(tgtaddr),
                              BuildNDOptionsVal(caplen - opt_offset, data + opt_offset, adapter));
}

void ICMPAnalyzer::Redirect(double t, const struct icmp* icmpp, int len, int caplen, const u_char*& data,
                            const IP_Hdr* ip_hdr, ICMPSessionAdapter* adapter) {
    EventHandlerPtr f = icmp_redirect;

    if ( ! f )
        return;

    IPAddr tgtaddr, dstaddr;

    if ( caplen >= (int)sizeof(in6_addr) )
        tgtaddr = IPAddr(*((const in6_addr*)data));

    if ( caplen >= 2 * (int)sizeof(in6_addr) )
        dstaddr = IPAddr(*((const in6_addr*)(data + sizeof(in6_addr))));

    int opt_offset = 2 * sizeof(in6_addr);

    adapter->EnqueueConnEvent(f, adapter->ConnVal(), BuildInfo(icmpp, len, true, ip_hdr),
                              make_intrusive<AddrVal>(tgtaddr), make_intrusive<AddrVal>(dstaddr),
                              BuildNDOptionsVal(caplen - opt_offset, data + opt_offset, adapter));
}

void ICMPAnalyzer::RouterSolicit(double t, const struct icmp* icmpp, int len, int caplen, const u_char*& data,
                                 const IP_Hdr* ip_hdr, ICMPSessionAdapter* adapter) {
    EventHandlerPtr f = icmp_router_solicitation;

    if ( ! f )
        return;

    adapter->EnqueueConnEvent(f, adapter->ConnVal(), BuildInfo(icmpp, len, true, ip_hdr),
                              BuildNDOptionsVal(caplen, data, adapter));
}

void ICMPAnalyzer::Context4(double t, const struct icmp* icmpp, int len, int caplen, const u_char*& data,
                            const IP_Hdr* ip_hdr, ICMPSessionAdapter* adapter) {
    EventHandlerPtr f = nullptr;

    switch ( icmpp->icmp_type ) {
        case ICMP_UNREACH: f = icmp_unreachable; break;

        case ICMP_TIMXCEED: f = icmp_time_exceeded; break;
    }

    if ( f )
        adapter->EnqueueConnEvent(f, adapter->ConnVal(), BuildInfo(icmpp, len, false, ip_hdr),
                                  val_mgr->Count(icmpp->icmp_code), ExtractICMP4Context(caplen, data));
}

void ICMPAnalyzer::Context6(double t, const struct icmp* icmpp, int len, int caplen, const u_char*& data,
                            const IP_Hdr* ip_hdr, ICMPSessionAdapter* adapter) {
    EventHandlerPtr f = nullptr;

    switch ( icmpp->icmp_type ) {
        case ICMP6_DST_UNREACH: f = icmp_unreachable; break;

        case ICMP6_PARAM_PROB: f = icmp_parameter_problem; break;

        case ICMP6_TIME_EXCEEDED: f = icmp_time_exceeded; break;

        case ICMP6_PACKET_TOO_BIG: f = icmp_packet_too_big; break;

        default: f = icmp_error_message; break;
    }

    if ( f )
        adapter->EnqueueConnEvent(f, adapter->ConnVal(), BuildInfo(icmpp, len, true, ip_hdr),
                                  val_mgr->Count(icmpp->icmp_code), ExtractICMP6Context(caplen, data));
}

zeek::VectorValPtr ICMPAnalyzer::BuildNDOptionsVal(int caplen, const u_char* data, ICMPSessionAdapter* adapter) {
    static auto icmp6_nd_option_type = id::find_type<RecordType>("icmp6_nd_option");
    static auto icmp6_nd_prefix_info_type = id::find_type<RecordType>("icmp6_nd_prefix_info");

    auto vv = make_intrusive<zeek::VectorVal>(id::find_type<VectorType>("icmp6_nd_options"));

    while ( caplen > 0 ) {
        // Must have at least type & length to continue parsing options.
        if ( caplen < 2 ) {
            adapter->Weird("truncated_ICMPv6_ND_options");
            break;
        }

        uint8_t type = *((const uint8_t*)data);
        uint16_t length = *((const uint8_t*)(data + 1));

        if ( length == 0 ) {
            adapter->Weird("zero_length_ICMPv6_ND_option");
            break;
        }

        auto rv = make_intrusive<zeek::RecordVal>(icmp6_nd_option_type);
        rv->Assign(0, val_mgr->Count(type));
        rv->Assign(1, val_mgr->Count(length));

        // Adjust length to be in units of bytes, exclude type/length fields.
        length = length * 8 - 2;

        data += 2;
        caplen -= 2;

        bool set_payload_field = false;

        // Only parse out known options that are there in full.
        switch ( type ) {
            case 1:
            case 2:
                // Source/Target Link-layer Address option
                {
                    if ( caplen >= length ) {
                        String* link_addr = new String(data, length, false);
                        rv->Assign(2, make_intrusive<StringVal>(link_addr));
                    }
                    else
                        set_payload_field = true;

                    break;
                }

            case 3:
                // Prefix Information option
                {
                    if ( caplen >= 30 ) {
                        auto info = make_intrusive<zeek::RecordVal>(icmp6_nd_prefix_info_type);
                        uint8_t prefix_len = *((const uint8_t*)(data));
                        bool L_flag = (*((const uint8_t*)(data + 1)) & 0x80) != 0;
                        bool A_flag = (*((const uint8_t*)(data + 1)) & 0x40) != 0;
                        uint32_t valid_life = *((const uint32_t*)(data + 2));
                        uint32_t prefer_life = *((const uint32_t*)(data + 6));
                        in6_addr prefix = *((const in6_addr*)(data + 14));
                        info->Assign(0, val_mgr->Count(prefix_len));
                        info->Assign(1, val_mgr->Bool(L_flag));
                        info->Assign(2, val_mgr->Bool(A_flag));
                        info->Assign(3, make_intrusive<IntervalVal>((double)ntohl(valid_life), Seconds));
                        info->Assign(4, make_intrusive<IntervalVal>((double)ntohl(prefer_life), Seconds));
                        info->Assign(5, make_intrusive<AddrVal>(IPAddr(prefix)));
                        rv->Assign(3, std::move(info));
                    }

                    else
                        set_payload_field = true;
                    break;
                }

            case 4:
                // Redirected Header option
                {
                    if ( caplen >= length ) {
                        const u_char* hdr = data + 6;
                        rv->Assign(4, ExtractICMP6Context(length - 6, hdr));
                    }

                    else
                        set_payload_field = true;

                    break;
                }

            case 5:
                // MTU option
                {
                    if ( caplen >= 6 )
                        rv->Assign(5, val_mgr->Count(ntohl(*((const uint32_t*)(data + 2)))));
                    else
                        set_payload_field = true;

                    break;
                }

            default: {
                set_payload_field = true;
                break;
            }
        }

        if ( set_payload_field ) {
            String* payload = new String(data, std::min((int)length, caplen), false);
            rv->Assign(6, make_intrusive<StringVal>(payload));
        }

        data += length;
        caplen -= length;

        vv->Assign(vv->Size(), std::move(rv));
    }

    return vv;
}

namespace zeek::packet_analysis::ICMP {

int ICMP4_counterpart(int icmp_type, int icmp_code, bool& is_one_way) {
    is_one_way = false;

    // Return the counterpart type if one exists.  This allows us
    // to track corresponding ICMP requests/replies.
    // Note that for the two-way ICMP messages, icmp_code is
    // always 0 (RFC 792).
    switch ( icmp_type ) {
        case ICMP_ECHO: return ICMP_ECHOREPLY;
        case ICMP_ECHOREPLY: return ICMP_ECHO;

        case ICMP_TSTAMP: return ICMP_TSTAMPREPLY;
        case ICMP_TSTAMPREPLY: return ICMP_TSTAMP;

        case ICMP_IREQ: return ICMP_IREQREPLY;
        case ICMP_IREQREPLY: return ICMP_IREQ;

        case ICMP_ROUTERSOLICIT: return ICMP_ROUTERADVERT;
        case ICMP_ROUTERADVERT: return ICMP_ROUTERSOLICIT;

        case ICMP_MASKREQ: return ICMP_MASKREPLY;
        case ICMP_MASKREPLY: return ICMP_MASKREQ;

        default: is_one_way = true; return icmp_code;
    }
}

int ICMP6_counterpart(int icmp_type, int icmp_code, bool& is_one_way) {
    is_one_way = false;

    switch ( icmp_type ) {
        case ICMP6_ECHO_REQUEST: return ICMP6_ECHO_REPLY;
        case ICMP6_ECHO_REPLY: return ICMP6_ECHO_REQUEST;

        case ND_ROUTER_SOLICIT: return ND_ROUTER_ADVERT;
        case ND_ROUTER_ADVERT: return ND_ROUTER_SOLICIT;

        case ND_NEIGHBOR_SOLICIT: return ND_NEIGHBOR_ADVERT;
        case ND_NEIGHBOR_ADVERT: return ND_NEIGHBOR_SOLICIT;

        case MLD_LISTENER_QUERY: return MLD_LISTENER_REPORT;
        case MLD_LISTENER_REPORT: return MLD_LISTENER_QUERY;

        // ICMP node information query and response respectively (not defined in
        // icmp6.h)
        case 139: return 140;
        case 140: return 139;

        // Home Agent Address Discovery Request Message and reply
        case 144: return 145;
        case 145:
            return 144;

            // TODO: Add further counterparts.

        default: is_one_way = true; return icmp_code;
    }
}

} // namespace zeek::packet_analysis::ICMP
