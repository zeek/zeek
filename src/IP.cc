// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/IP.h"

#include <netinet/icmp6.h>
#include <netinet/in.h>
#include <sys/types.h>

#include "zeek/IPAddr.h"
#include "zeek/Reporter.h"
#include "zeek/Type.h"
#include "zeek/Val.h"
#include "zeek/ZeekString.h"

namespace zeek {

bool IPv6_Hdr::IsOptionTruncated(uint16_t off) const {
    if ( Length() < off ) {
        reporter->Weird("truncated_IPv6_option");
        return true;
    }

    return false;
}

static VectorValPtr BuildOptionsVal(const u_char* data, int len) {
    auto vv = make_intrusive<VectorVal>(id::find_type<VectorType>("ip6_options"));

    while ( len > 0 && static_cast<size_t>(len) >= sizeof(struct ip6_opt) ) {
        static auto ip6_option_type = id::find_type<RecordType>("ip6_option");
        const struct ip6_opt* opt = (const struct ip6_opt*)data;
        auto rv = make_intrusive<RecordVal>(ip6_option_type);
        rv->Assign(0, opt->ip6o_type);

        if ( opt->ip6o_type == 0 ) {
            // Pad1 option
            rv->Assign(1, 0);
            rv->Assign(2, val_mgr->EmptyString());
            data += sizeof(uint8_t);
            len -= sizeof(uint8_t);
        }
        else {
            // PadN or other option
            uint16_t off = 2 * sizeof(uint8_t);

            if ( len < opt->ip6o_len + off )
                break;

            rv->Assign(1, opt->ip6o_len);
            rv->Assign(2, new String(data + off, opt->ip6o_len, true));
            data += opt->ip6o_len + off;
            len -= opt->ip6o_len + off;
        }

        vv->Assign(vv->Size(), std::move(rv));
    }

    return vv;
}

RecordValPtr IPv6_Hdr::ToVal(VectorValPtr chain) const {
    RecordValPtr rv;

    switch ( type ) {
        case IPPROTO_IPV6: {
            static auto ip6_hdr_type = id::find_type<RecordType>("ip6_hdr");
            rv = make_intrusive<RecordVal>(ip6_hdr_type);
            const struct ip6_hdr* ip6 = (const struct ip6_hdr*)data;
            rv->Assign(0, static_cast<uint32_t>(ntohl(ip6->ip6_flow) & 0x0ff00000) >> 20);
            rv->Assign(1, static_cast<uint32_t>(ntohl(ip6->ip6_flow) & 0x000fffff));
            rv->Assign(2, ntohs(ip6->ip6_plen));
            rv->Assign(3, ip6->ip6_nxt);
            rv->Assign(4, ip6->ip6_hlim);
            rv->Assign(5, make_intrusive<AddrVal>(IPAddr(ip6->ip6_src)));
            rv->Assign(6, make_intrusive<AddrVal>(IPAddr(ip6->ip6_dst)));
            if ( ! chain )
                chain = make_intrusive<VectorVal>(id::find_type<VectorType>("ip6_ext_hdr_chain"));
            rv->Assign(7, std::move(chain));
        } break;

        case IPPROTO_HOPOPTS: {
            uint16_t off = 2 * sizeof(uint8_t);
            if ( IsOptionTruncated(off) )
                return nullptr;

            static auto ip6_hopopts_type = id::find_type<RecordType>("ip6_hopopts");
            rv = make_intrusive<RecordVal>(ip6_hopopts_type);
            const struct ip6_hbh* hbh = (const struct ip6_hbh*)data;
            rv->Assign(0, hbh->ip6h_nxt);
            rv->Assign(1, hbh->ip6h_len);
            rv->Assign(2, BuildOptionsVal(data + off, Length() - off));
        } break;

        case IPPROTO_DSTOPTS: {
            uint16_t off = 2 * sizeof(uint8_t);
            if ( IsOptionTruncated(off) )
                return nullptr;

            static auto ip6_dstopts_type = id::find_type<RecordType>("ip6_dstopts");
            rv = make_intrusive<RecordVal>(ip6_dstopts_type);
            const struct ip6_dest* dst = (const struct ip6_dest*)data;
            rv->Assign(0, dst->ip6d_nxt);
            rv->Assign(1, dst->ip6d_len);
            rv->Assign(2, BuildOptionsVal(data + off, Length() - off));
        } break;

        case IPPROTO_ROUTING: {
            uint16_t off = 4 * sizeof(uint8_t);
            if ( IsOptionTruncated(off) )
                return nullptr;

            static auto ip6_routing_type = id::find_type<RecordType>("ip6_routing");
            rv = make_intrusive<RecordVal>(ip6_routing_type);
            const struct ip6_rthdr* rt = (const struct ip6_rthdr*)data;
            rv->Assign(0, rt->ip6r_nxt);
            rv->Assign(1, rt->ip6r_len);
            rv->Assign(2, rt->ip6r_type);
            rv->Assign(3, rt->ip6r_segleft);
            rv->Assign(4, new String(data + off, Length() - off, true));
        } break;

        case IPPROTO_FRAGMENT: {
            static auto ip6_fragment_type = id::find_type<RecordType>("ip6_fragment");
            rv = make_intrusive<RecordVal>(ip6_fragment_type);
            const struct ip6_frag* frag = (const struct ip6_frag*)data;
            rv->Assign(0, frag->ip6f_nxt);
            rv->Assign(1, frag->ip6f_reserved);
            rv->Assign(2, (ntohs(frag->ip6f_offlg) & 0xfff8) >> 3);
            rv->Assign(3, (ntohs(frag->ip6f_offlg) & 0x0006) >> 1);
            rv->Assign(4, static_cast<bool>(ntohs(frag->ip6f_offlg) & 0x0001));
            rv->Assign(5, static_cast<uint32_t>(ntohl(frag->ip6f_ident)));
        } break;

        case IPPROTO_AH: {
            static auto ip6_ah_type = id::find_type<RecordType>("ip6_ah");
            rv = make_intrusive<RecordVal>(ip6_ah_type);
            rv->Assign(0, ((ip6_ext*)data)->ip6e_nxt);
            rv->Assign(1, ((ip6_ext*)data)->ip6e_len);
            rv->Assign(2, ntohs(((uint16_t*)data)[1]));
            rv->Assign(3, static_cast<uint32_t>(ntohl(((uint32_t*)data)[1])));

            if ( Length() >= 12 ) {
                // Sequence Number and ICV fields can only be extracted if
                // Payload Len was non-zero for this header.
                rv->Assign(4, static_cast<uint32_t>(ntohl(((uint32_t*)data)[2])));
                uint16_t off = 3 * sizeof(uint32_t);
                rv->Assign(5, new String(data + off, Length() - off, true));
            }
        } break;

        case IPPROTO_ESP: {
            static auto ip6_esp_type = id::find_type<RecordType>("ip6_esp");
            rv = make_intrusive<RecordVal>(ip6_esp_type);
            const uint32_t* esp = (const uint32_t*)data;
            rv->Assign(0, static_cast<uint32_t>(ntohl(esp[0])));
            rv->Assign(1, static_cast<uint32_t>(ntohl(esp[1])));
        } break;

        case IPPROTO_MOBILITY: {
            static auto ip6_mob_type = id::find_type<RecordType>("ip6_mobility_hdr");
            rv = make_intrusive<RecordVal>(ip6_mob_type);
            const struct ip6_mobility* mob = (const struct ip6_mobility*)data;
            rv->Assign(0, mob->ip6mob_payload);
            rv->Assign(1, mob->ip6mob_len);
            rv->Assign(2, mob->ip6mob_type);
            rv->Assign(3, mob->ip6mob_rsv);
            rv->Assign(4, ntohs(mob->ip6mob_chksum));

            static auto ip6_mob_msg_type = id::find_type<RecordType>("ip6_mobility_msg");
            auto msg = make_intrusive<RecordVal>(ip6_mob_msg_type);
            msg->Assign(0, mob->ip6mob_type);

            uint16_t off = sizeof(ip6_mobility);
            const u_char* msg_data = data + off;

            static auto ip6_mob_brr_type = id::find_type<RecordType>("ip6_mobility_brr");
            static auto ip6_mob_hoti_type = id::find_type<RecordType>("ip6_mobility_hoti");
            static auto ip6_mob_coti_type = id::find_type<RecordType>("ip6_mobility_coti");
            static auto ip6_mob_hot_type = id::find_type<RecordType>("ip6_mobility_hot");
            static auto ip6_mob_cot_type = id::find_type<RecordType>("ip6_mobility_cot");
            static auto ip6_mob_bu_type = id::find_type<RecordType>("ip6_mobility_bu");
            static auto ip6_mob_back_type = id::find_type<RecordType>("ip6_mobility_back");
            static auto ip6_mob_be_type = id::find_type<RecordType>("ip6_mobility_be");

            switch ( mob->ip6mob_type ) {
                case 0: {
                    off += sizeof(uint16_t);
                    if ( IsOptionTruncated(off) )
                        break;

                    auto m = make_intrusive<RecordVal>(ip6_mob_brr_type);
                    m->Assign(0, ntohs(*((uint16_t*)msg_data)));
                    m->Assign(1, BuildOptionsVal(data + off, Length() - off));
                    msg->Assign(1, std::move(m));
                    break;
                }

                case 1: {
                    off += sizeof(uint16_t) + sizeof(uint64_t);
                    if ( IsOptionTruncated(off) )
                        break;

                    auto m = make_intrusive<RecordVal>(ip6_mob_hoti_type);
                    m->Assign(0, ntohs(*((uint16_t*)msg_data)));
                    m->Assign(1, ntohll(*((uint64_t*)(msg_data + sizeof(uint16_t)))));
                    m->Assign(2, BuildOptionsVal(data + off, Length() - off));
                    msg->Assign(2, std::move(m));
                    break;
                }

                case 2: {
                    off += sizeof(uint16_t) + sizeof(uint64_t);
                    if ( IsOptionTruncated(off) )
                        break;

                    auto m = make_intrusive<RecordVal>(ip6_mob_coti_type);
                    m->Assign(0, ntohs(*((uint16_t*)msg_data)));
                    m->Assign(1, ntohll(*((uint64_t*)(msg_data + sizeof(uint16_t)))));
                    m->Assign(2, BuildOptionsVal(data + off, Length() - off));
                    msg->Assign(3, std::move(m));
                    break;
                }

                case 3: {
                    off += sizeof(uint16_t) + 2 * sizeof(uint64_t);
                    if ( IsOptionTruncated(off) )
                        break;

                    auto m = make_intrusive<RecordVal>(ip6_mob_hot_type);
                    m->Assign(0, ntohs(*((uint16_t*)msg_data)));
                    m->Assign(1, ntohll(*((uint64_t*)(msg_data + sizeof(uint16_t)))));
                    m->Assign(2, ntohll(*((uint64_t*)(msg_data + sizeof(uint16_t) + sizeof(uint64_t)))));
                    m->Assign(3, BuildOptionsVal(data + off, Length() - off));
                    msg->Assign(4, std::move(m));
                    break;
                }

                case 4: {
                    off += sizeof(uint16_t) + 2 * sizeof(uint64_t);
                    if ( IsOptionTruncated(off) )
                        break;

                    auto m = make_intrusive<RecordVal>(ip6_mob_cot_type);
                    m->Assign(0, ntohs(*((uint16_t*)msg_data)));
                    m->Assign(1, ntohll(*((uint64_t*)(msg_data + sizeof(uint16_t)))));
                    m->Assign(2, ntohll(*((uint64_t*)(msg_data + sizeof(uint16_t) + sizeof(uint64_t)))));
                    m->Assign(3, BuildOptionsVal(data + off, Length() - off));
                    msg->Assign(5, std::move(m));
                    break;
                }

                case 5: {
                    off += 3 * sizeof(uint16_t);
                    if ( IsOptionTruncated(off) )
                        break;

                    auto m = make_intrusive<RecordVal>(ip6_mob_bu_type);
                    m->Assign(0, ntohs(*((uint16_t*)msg_data)));
                    m->Assign(1, static_cast<bool>(ntohs(*((uint16_t*)(msg_data + sizeof(uint16_t)))) & 0x8000));
                    m->Assign(2, static_cast<bool>(ntohs(*((uint16_t*)(msg_data + sizeof(uint16_t)))) & 0x4000));
                    m->Assign(3, static_cast<bool>(ntohs(*((uint16_t*)(msg_data + sizeof(uint16_t)))) & 0x2000));
                    m->Assign(4, static_cast<bool>(ntohs(*((uint16_t*)(msg_data + sizeof(uint16_t)))) & 0x1000));
                    m->Assign(5, ntohs(*((uint16_t*)(msg_data + 2 * sizeof(uint16_t)))));
                    m->Assign(6, BuildOptionsVal(data + off, Length() - off));
                    msg->Assign(6, std::move(m));
                    break;
                }

                case 6: {
                    off += 3 * sizeof(uint16_t);
                    if ( IsOptionTruncated(off) )
                        break;

                    auto m = make_intrusive<RecordVal>(ip6_mob_back_type);
                    m->Assign(0, *((uint8_t*)msg_data));
                    m->Assign(1, static_cast<bool>(*((uint8_t*)(msg_data + sizeof(uint8_t))) & 0x80));
                    m->Assign(2, ntohs(*((uint16_t*)(msg_data + sizeof(uint16_t)))));
                    m->Assign(3, ntohs(*((uint16_t*)(msg_data + 2 * sizeof(uint16_t)))));
                    m->Assign(4, BuildOptionsVal(data + off, Length() - off));
                    msg->Assign(7, std::move(m));
                    break;
                }

                case 7: {
                    off += sizeof(uint16_t) + sizeof(in6_addr);
                    if ( IsOptionTruncated(off) )
                        break;

                    auto m = make_intrusive<RecordVal>(ip6_mob_be_type);
                    m->Assign(0, *((uint8_t*)msg_data));
                    const in6_addr* hoa = (const in6_addr*)(msg_data + sizeof(uint16_t));
                    m->Assign(1, make_intrusive<AddrVal>(IPAddr(*hoa)));
                    m->Assign(2, BuildOptionsVal(data + off, Length() - off));
                    msg->Assign(8, std::move(m));
                    break;
                }

                default: reporter->Weird("unknown_mobility_type", util::fmt("%d", mob->ip6mob_type)); break;
            }

            rv->Assign(5, std::move(msg));
        } break;

        default: break;
    }

    return rv;
}

RecordValPtr IPv6_Hdr::ToVal() const { return ToVal(nullptr); }

IPAddr IP_Hdr::IPHeaderSrcAddr() const { return ip4 ? IPAddr(ip4->ip_src) : IPAddr(ip6->ip6_src); }

IPAddr IP_Hdr::IPHeaderDstAddr() const { return ip4 ? IPAddr(ip4->ip_dst) : IPAddr(ip6->ip6_dst); }

IPAddr IP_Hdr::SrcAddr() const { return ip4 ? IPAddr(ip4->ip_src) : ip6_hdrs->SrcAddr(); }

IPAddr IP_Hdr::DstAddr() const { return ip4 ? IPAddr(ip4->ip_dst) : ip6_hdrs->DstAddr(); }

RecordValPtr IP_Hdr::ToIPHdrVal() const {
    RecordValPtr rval;

    if ( ip4 ) {
        static auto ip4_hdr_type = id::find_type<RecordType>("ip4_hdr");
        rval = make_intrusive<RecordVal>(ip4_hdr_type);
        rval->Assign(0, ip4->ip_hl * 4);
        rval->Assign(1, ip4->ip_tos);
        rval->Assign(2, ntohs(ip4->ip_len));
        rval->Assign(3, ntohs(ip4->ip_id));
        rval->Assign(4, DF());
        rval->Assign(5, MF());
        rval->Assign(6, FragOffset()); // 13 bit offset as multiple of 8
        rval->Assign(7, ip4->ip_ttl);
        rval->Assign(8, ip4->ip_p);
        rval->Assign(9, ntohs(ip4->ip_sum));
        rval->Assign(10, make_intrusive<AddrVal>(ip4->ip_src.s_addr));
        rval->Assign(11, make_intrusive<AddrVal>(ip4->ip_dst.s_addr));
    }
    else {
        rval = ((*ip6_hdrs)[0])->ToVal(ip6_hdrs->ToVal());
    }

    return rval;
}

RecordValPtr IP_Hdr::ToPktHdrVal() const {
    static auto pkt_hdr_type = id::find_type<RecordType>("pkt_hdr");
    return ToPktHdrVal(make_intrusive<RecordVal>(pkt_hdr_type), 0);
}

RecordValPtr IP_Hdr::ToPktHdrVal(RecordValPtr pkt_hdr, int sindex) const {
    static auto tcp_hdr_type = id::find_type<RecordType>("tcp_hdr");
    static auto udp_hdr_type = id::find_type<RecordType>("udp_hdr");
    static auto icmp_hdr_type = id::find_type<RecordType>("icmp_hdr");

    if ( ip4 )
        pkt_hdr->Assign(sindex + 0, ToIPHdrVal());
    else
        pkt_hdr->Assign(sindex + 1, ToIPHdrVal());

    // L4 header.
    const u_char* data = Payload();

    int proto = NextProto();
    switch ( proto ) {
        case IPPROTO_TCP: {
            if ( PayloadLen() < sizeof(struct tcphdr) )
                break;

            const struct tcphdr* tp = (const struct tcphdr*)data;
            auto tcp_hdr = make_intrusive<RecordVal>(tcp_hdr_type);

            int tcp_hdr_len = tp->th_off * 4;

            // account for cases in which the payload length in the TCP header is not set,
            // or is set to an impossible value. In these cases, return 0.
            int data_len = 0;
            auto payload_len = PayloadLen();
            if ( payload_len >= tcp_hdr_len )
                data_len = payload_len - tcp_hdr_len;

            tcp_hdr->Assign(0, val_mgr->Port(ntohs(tp->th_sport), TRANSPORT_TCP));
            tcp_hdr->Assign(1, val_mgr->Port(ntohs(tp->th_dport), TRANSPORT_TCP));
            tcp_hdr->Assign(2, static_cast<uint32_t>(ntohl(tp->th_seq)));
            tcp_hdr->Assign(3, static_cast<uint32_t>(ntohl(tp->th_ack)));
            tcp_hdr->Assign(4, tcp_hdr_len);
            tcp_hdr->Assign(5, data_len);
            tcp_hdr->Assign(6, tp->th_x2);
            tcp_hdr->Assign(7, tp->th_flags);
            tcp_hdr->Assign(8, ntohs(tp->th_win));

            pkt_hdr->Assign(sindex + 2, std::move(tcp_hdr));
            break;
        }

        case IPPROTO_UDP: {
            if ( PayloadLen() < sizeof(struct udphdr) )
                break;

            const struct udphdr* up = (const struct udphdr*)data;
            auto udp_hdr = make_intrusive<RecordVal>(udp_hdr_type);

            udp_hdr->Assign(0, val_mgr->Port(ntohs(up->uh_sport), TRANSPORT_UDP));
            udp_hdr->Assign(1, val_mgr->Port(ntohs(up->uh_dport), TRANSPORT_UDP));
            udp_hdr->Assign(2, ntohs(up->uh_ulen));

            pkt_hdr->Assign(sindex + 3, std::move(udp_hdr));
            break;
        }

        case IPPROTO_ICMP: {
            if ( PayloadLen() < sizeof(struct icmp) )
                break;

            const struct icmp* icmpp = (const struct icmp*)data;
            auto icmp_hdr = make_intrusive<RecordVal>(icmp_hdr_type);

            icmp_hdr->Assign(0, icmpp->icmp_type);

            pkt_hdr->Assign(sindex + 4, std::move(icmp_hdr));
            break;
        }

        case IPPROTO_ICMPV6: {
            if ( PayloadLen() < sizeof(struct icmp6_hdr) )
                break;

            const struct icmp6_hdr* icmpp = (const struct icmp6_hdr*)data;
            auto icmp_hdr = make_intrusive<RecordVal>(icmp_hdr_type);

            icmp_hdr->Assign(0, icmpp->icmp6_type);

            pkt_hdr->Assign(sindex + 4, std::move(icmp_hdr));
            break;
        }

        default: {
            // This is not a protocol we understand.
            break;
        }
    }

    return pkt_hdr;
}

static inline bool isIPv6ExtHeader(uint8_t type) {
    switch ( type ) {
        case IPPROTO_HOPOPTS:
        case IPPROTO_ROUTING:
        case IPPROTO_DSTOPTS:
        case IPPROTO_FRAGMENT:
        case IPPROTO_AH:
        case IPPROTO_ESP:
        case IPPROTO_MOBILITY: return true;
        default: return false;
    }
}

IPv6_Hdr_Chain::~IPv6_Hdr_Chain() {
    for ( size_t i = 0; i < chain.size(); ++i )
        delete chain[i];
    delete homeAddr;
    delete finalDst;
}

void IPv6_Hdr_Chain::Init(const struct ip6_hdr* ip6, uint64_t total_len, bool set_next, uint16_t next) {
    length = 0;
    uint8_t current_type, next_type;
    next_type = IPPROTO_IPV6;
    const u_char* hdrs = (const u_char*)ip6;

    if ( total_len < (int)sizeof(struct ip6_hdr) ) {
        reporter->InternalWarning("truncated IP header in IPv6_HdrChain::Init");
        return;
    }

    do {
        // We can't determine a given header's length if there's less than
        // two bytes of data available (2nd byte of extension headers is length)
        if ( total_len < 2 )
            return;

        current_type = next_type;
        IPv6_Hdr* p = new IPv6_Hdr(current_type, hdrs);

        next_type = p->NextHdr();
        uint16_t cur_len = p->Length();

        // If this header is truncated, don't add it to chain, don't go further.
        if ( cur_len > total_len ) {
            delete p;
            return;
        }

        if ( set_next && next_type == IPPROTO_FRAGMENT ) {
            p->ChangeNext(next);
            next_type = next;
        }

        chain.push_back(p);

        // Check for routing headers and remember final destination address.
        if ( current_type == IPPROTO_ROUTING )
            ProcessRoutingHeader((const struct ip6_rthdr*)hdrs, cur_len);

        // Only Mobile IPv6 has a destination option we care about right now.
        if ( current_type == IPPROTO_DSTOPTS )
            ProcessDstOpts((const struct ip6_dest*)hdrs, cur_len);

        hdrs += cur_len;
        length += cur_len;
        total_len -= cur_len;

    } while ( current_type != IPPROTO_FRAGMENT && current_type != IPPROTO_ESP && current_type != IPPROTO_MOBILITY &&
              isIPv6ExtHeader(next_type) );
}

bool IPv6_Hdr_Chain::IsFragment() const {
    if ( chain.empty() ) {
        reporter->InternalWarning("empty IPv6 header chain");
        return false;
    }

    return chain[chain.size() - 1]->Type() == IPPROTO_FRAGMENT;
}

IPAddr IPv6_Hdr_Chain::SrcAddr() const {
    if ( homeAddr )
        return {*homeAddr};

    if ( chain.empty() ) {
        reporter->InternalWarning("empty IPv6 header chain");
        return {};
    }

    return IPAddr{((const struct ip6_hdr*)(chain[0]->Data()))->ip6_src};
}

IPAddr IPv6_Hdr_Chain::DstAddr() const {
    if ( finalDst )
        return {*finalDst};

    if ( chain.empty() ) {
        reporter->InternalWarning("empty IPv6 header chain");
        return {};
    }

    return IPAddr{((const struct ip6_hdr*)(chain[0]->Data()))->ip6_dst};
}

void IPv6_Hdr_Chain::ProcessRoutingHeader(const struct ip6_rthdr* r, uint16_t len) {
    if ( finalDst ) {
        // RFC 2460 section 4.1 says Routing should occur at most once.
        reporter->Weird(SrcAddr(), DstAddr(), "multiple_routing_headers");
        return;
    }

    // Last 16 bytes of header (for all known types) is the address we want.
    const in6_addr* addr = (const in6_addr*)(((const u_char*)r) + len - 16);

    switch ( r->ip6r_type ) {
        case 0: // Defined by RFC 2460, deprecated by RFC 5095
        {
            if ( r->ip6r_segleft > 0 && r->ip6r_len >= 2 ) {
                if ( r->ip6r_len % 2 == 0 )
                    finalDst = new IPAddr(*addr);
                else
                    reporter->Weird(SrcAddr(), DstAddr(), "odd_routing0_len");
            }

            // Always raise a weird since this type is deprecated.
            reporter->Weird(SrcAddr(), DstAddr(), "routing0_hdr");
        } break;

        case 2: // Defined by Mobile IPv6 RFC 6275.
        {
            if ( r->ip6r_segleft > 0 ) {
                if ( r->ip6r_len == 2 )
                    finalDst = new IPAddr(*addr);
                else
                    reporter->Weird(SrcAddr(), DstAddr(), "bad_routing2_len");
            }
        } break;

        default: reporter->Weird(SrcAddr(), DstAddr(), "unknown_routing_type", util::fmt("%d", r->ip6r_type)); break;
    }
}

void IPv6_Hdr_Chain::ProcessDstOpts(const struct ip6_dest* d, uint16_t len) {
    // Skip two bytes to get the beginning of the first option structure. These
    // two bytes are the protocol for the next header and extension header length,
    // already known to exist before calling this method.  See header format:
    // https://datatracker.ietf.org/doc/html/rfc8200#section-4.6
    assert(len >= 2);

    const u_char* data = (const u_char*)d;
    len -= 2 * sizeof(uint8_t);
    data += 2 * sizeof(uint8_t);

    while ( len > 0 ) {
        const struct ip6_opt* opt = (const struct ip6_opt*)data;
        switch ( opt->ip6o_type ) {
            case 0:
                // If option type is zero, it's a Pad0 and can be just a single
                // byte in width. Skip over it.
                data += sizeof(uint8_t);
                len -= sizeof(uint8_t);
                break;
            default: {
                // Double-check that the len can hold the whole option structure.
                // Otherwise we get a buffer-overflow when we check the option_len.
                // Also check that it holds everything for the option itself.
                if ( len < sizeof(struct ip6_opt) || len < sizeof(struct ip6_opt) + opt->ip6o_len ) {
                    reporter->Weird(SrcAddr(), DstAddr(), "bad_ipv6_dest_opt_len");
                    len = 0;
                    break;
                }

                if ( opt->ip6o_type == 201 ) // Home Address Option, Mobile IPv6 RFC 6275 section 6.3
                {
                    if ( opt->ip6o_len == sizeof(struct in6_addr) ) {
                        if ( homeAddr )
                            reporter->Weird(SrcAddr(), DstAddr(), "multiple_home_addr_opts");
                        else
                            homeAddr = new IPAddr(*((const in6_addr*)(data + sizeof(struct ip6_opt))));
                    }
                    else
                        reporter->Weird(SrcAddr(), DstAddr(), "bad_home_addr_len");
                }

                data += sizeof(struct ip6_opt) + opt->ip6o_len;
                len -= sizeof(struct ip6_opt) + opt->ip6o_len;
            } break;
        }
    }
}

VectorValPtr IPv6_Hdr_Chain::ToVal() const {
    static auto ip6_ext_hdr_type = id::find_type<RecordType>("ip6_ext_hdr");
    static auto ip6_hopopts_type = id::find_type<RecordType>("ip6_hopopts");
    static auto ip6_dstopts_type = id::find_type<RecordType>("ip6_dstopts");
    static auto ip6_routing_type = id::find_type<RecordType>("ip6_routing");
    static auto ip6_fragment_type = id::find_type<RecordType>("ip6_fragment");
    static auto ip6_ah_type = id::find_type<RecordType>("ip6_ah");
    static auto ip6_esp_type = id::find_type<RecordType>("ip6_esp");
    static auto ip6_ext_hdr_chain_type = id::find_type<VectorType>("ip6_ext_hdr_chain");
    auto rval = make_intrusive<VectorVal>(ip6_ext_hdr_chain_type);

    for ( size_t i = 1; i < chain.size(); ++i ) {
        auto v = chain[i]->ToVal();
        auto ext_hdr = make_intrusive<RecordVal>(ip6_ext_hdr_type);
        uint8_t type = chain[i]->Type();
        ext_hdr->Assign(0, type);

        switch ( type ) {
            case IPPROTO_HOPOPTS: ext_hdr->Assign(1, std::move(v)); break;
            case IPPROTO_DSTOPTS: ext_hdr->Assign(2, std::move(v)); break;
            case IPPROTO_ROUTING: ext_hdr->Assign(3, std::move(v)); break;
            case IPPROTO_FRAGMENT: ext_hdr->Assign(4, std::move(v)); break;
            case IPPROTO_AH: ext_hdr->Assign(5, std::move(v)); break;
            case IPPROTO_ESP: ext_hdr->Assign(6, std::move(v)); break;
            case IPPROTO_MOBILITY: ext_hdr->Assign(7, std::move(v)); break;
            default: reporter->InternalWarning("IPv6_Hdr_Chain bad header %d", type); continue;
        }

        rval->Assign(rval->Size(), std::move(ext_hdr));
    }

    return rval;
}

IP_Hdr* IP_Hdr::Copy() const {
    char* new_hdr = new char[HdrLen()];

    if ( ip4 ) {
        memcpy(new_hdr, ip4, HdrLen());
        return new IP_Hdr((const struct ip*)new_hdr, true);
    }

    memcpy(new_hdr, ip6, HdrLen());
    const struct ip6_hdr* new_ip6 = (const struct ip6_hdr*)new_hdr;
    IPv6_Hdr_Chain* new_ip6_hdrs = ip6_hdrs->Copy(new_ip6);
    return new IP_Hdr(new_ip6, true, 0, new_ip6_hdrs);
}

IPv6_Hdr_Chain* IPv6_Hdr_Chain::Copy(const ip6_hdr* new_hdr) const {
    IPv6_Hdr_Chain* rval = new IPv6_Hdr_Chain;
    rval->length = length;

    if ( homeAddr )
        rval->homeAddr = new IPAddr(*homeAddr);

    if ( finalDst )
        rval->finalDst = new IPAddr(*finalDst);

    if ( chain.empty() ) {
        reporter->InternalWarning("empty IPv6 header chain");
        delete rval;
        return nullptr;
    }

    const u_char* new_data = (const u_char*)new_hdr;
    const u_char* old_data = chain[0]->Data();

    for ( size_t i = 0; i < chain.size(); ++i ) {
        int off = chain[i]->Data() - old_data;
        rval->chain.push_back(new IPv6_Hdr(chain[i]->Type(), new_data + off));
    }

    return rval;
}

} // namespace zeek
