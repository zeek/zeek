// See the file "COPYING" in the main distribution directory for copyright.

#include "IP.h"
#include "Type.h"
#include "Val.h"
#include "Var.h"

static RecordType* ip4_hdr_type = 0;
static RecordType* ip6_hdr_type = 0;
static RecordType* ip6_ext_hdr_type = 0;
static RecordType* ip6_option_type = 0;
static RecordType* ip6_hopopts_type = 0;
static RecordType* ip6_dstopts_type = 0;
static RecordType* ip6_routing_type = 0;
static RecordType* ip6_fragment_type = 0;
static RecordType* ip6_ah_type = 0;
static RecordType* ip6_esp_type = 0;

static inline RecordType* hdrType(RecordType*& type, const char* name)
	{
	if ( ! type )
		type = internal_type(name)->AsRecordType();

	return type;
	}

static VectorVal* BuildOptionsVal(const u_char* data, uint16 len)
	{
	VectorVal* vv = new VectorVal(new VectorType(
	        hdrType(ip6_option_type, "ip6_option")->Ref()));

	while ( len > 0 )
		{
		const struct ip6_opt* opt = (const struct ip6_opt*) data;
		RecordVal* rv = new RecordVal(ip6_option_type);
		rv->Assign(0, new Val(opt->ip6o_type, TYPE_COUNT));

		if ( opt->ip6o_type == 0 )
			{
			// Pad1 option
			rv->Assign(1, new Val(0, TYPE_COUNT));
			rv->Assign(2, new StringVal(""));
			data += sizeof(uint8);
			len -= sizeof(uint8);
			}
		else
			{
			// PadN or other option
			uint16 off = 2 * sizeof(uint8);
			rv->Assign(1, new Val(opt->ip6o_len, TYPE_COUNT));
			rv->Assign(2, new StringVal(
			        new BroString(data + off, opt->ip6o_len, 1)));
			data += opt->ip6o_len + off;
			len -= opt->ip6o_len + off;
			}

		vv->Assign(vv->Size(), rv, 0);
		}

	return vv;
	}

RecordVal* IPv6_Hdr::BuildRecordVal(VectorVal* chain) const
	{
	RecordVal* rv = 0;

	switch ( type ) {
	case IPPROTO_IPV6:
		{
		rv = new RecordVal(hdrType(ip6_hdr_type, "ip6_hdr"));
		const struct ip6_hdr* ip6 = (const struct ip6_hdr*)data;
		rv->Assign(0, new Val((ntohl(ip6->ip6_flow) & 0x0ff00000)>>20, TYPE_COUNT));
		rv->Assign(1, new Val(ntohl(ip6->ip6_flow) & 0x000fffff, TYPE_COUNT));
		rv->Assign(2, new Val(ntohs(ip6->ip6_plen), TYPE_COUNT));
		rv->Assign(3, new Val(ip6->ip6_nxt, TYPE_COUNT));
		rv->Assign(4, new Val(ip6->ip6_hlim, TYPE_COUNT));
		rv->Assign(5, new AddrVal(ip6->ip6_src));
		rv->Assign(6, new AddrVal(ip6->ip6_dst));
		if ( ! chain )
			chain = new VectorVal(new VectorType(
			        hdrType(ip6_ext_hdr_type, "ip6_ext_hdr")->Ref()));
		rv->Assign(7, chain);
		}
		break;

	case IPPROTO_HOPOPTS:
		{
		rv = new RecordVal(hdrType(ip6_hopopts_type, "ip6_hopopts"));
		const struct ip6_hbh* hbh = (const struct ip6_hbh*)data;
		rv->Assign(0, new Val(hbh->ip6h_nxt, TYPE_COUNT));
		rv->Assign(1, new Val(hbh->ip6h_len, TYPE_COUNT));
		uint16 off = 2 * sizeof(uint8);
		rv->Assign(2, BuildOptionsVal(data + off, Length() - off));

		}
		break;

	case IPPROTO_DSTOPTS:
		{
		rv = new RecordVal(hdrType(ip6_dstopts_type, "ip6_dstopts"));
		const struct ip6_dest* dst = (const struct ip6_dest*)data;
		rv->Assign(0, new Val(dst->ip6d_nxt, TYPE_COUNT));
		rv->Assign(1, new Val(dst->ip6d_len, TYPE_COUNT));
		uint16 off = 2 * sizeof(uint8);
		rv->Assign(2, BuildOptionsVal(data + off, Length() - off));
		}
		break;

	case IPPROTO_ROUTING:
		{
		rv = new RecordVal(hdrType(ip6_routing_type, "ip6_routing"));
		const struct ip6_rthdr* rt = (const struct ip6_rthdr*)data;
		rv->Assign(0, new Val(rt->ip6r_nxt, TYPE_COUNT));
		rv->Assign(1, new Val(rt->ip6r_len, TYPE_COUNT));
		rv->Assign(2, new Val(rt->ip6r_type, TYPE_COUNT));
		rv->Assign(3, new Val(rt->ip6r_segleft, TYPE_COUNT));
		uint16 off = 4 * sizeof(uint8);
		rv->Assign(4, new StringVal(new BroString(data + off, Length() - off, 1)));
		}
		break;

	case IPPROTO_FRAGMENT:
		{
		rv = new RecordVal(hdrType(ip6_fragment_type, "ip6_fragment"));
		const struct ip6_frag* frag = (const struct ip6_frag*)data;
		rv->Assign(0, new Val(frag->ip6f_nxt, TYPE_COUNT));
		rv->Assign(1, new Val(frag->ip6f_reserved, TYPE_COUNT));
		rv->Assign(2, new Val((ntohs(frag->ip6f_offlg) & 0xfff8)>>3, TYPE_COUNT));
		rv->Assign(3, new Val((ntohs(frag->ip6f_offlg) & 0x0006)>>1, TYPE_COUNT));
		rv->Assign(4, new Val(ntohs(frag->ip6f_offlg) & 0x0001, TYPE_BOOL));
		rv->Assign(5, new Val(ntohl(frag->ip6f_ident), TYPE_COUNT));
		}
		break;

	case IPPROTO_AH:
		{
		rv = new RecordVal(hdrType(ip6_ah_type, "ip6_ah"));
		rv->Assign(0, new Val(((ip6_ext*)data)->ip6e_nxt, TYPE_COUNT));
		rv->Assign(1, new Val(((ip6_ext*)data)->ip6e_len, TYPE_COUNT));
		rv->Assign(2, new Val(ntohs(((uint16*)data)[1]), TYPE_COUNT));
		rv->Assign(3, new Val(ntohl(((uint32*)data)[1]), TYPE_COUNT));
		rv->Assign(4, new Val(ntohl(((uint32*)data)[2]), TYPE_COUNT));
		uint16 off = 3 * sizeof(uint32);
		rv->Assign(5, new StringVal(new BroString(data + off, Length() - off, 1)));
		}
		break;

	case IPPROTO_ESP:
		{
		rv = new RecordVal(hdrType(ip6_esp_type, "ip6_esp"));
		const uint32* esp = (const uint32*)data;
		rv->Assign(0, new Val(ntohl(esp[0]), TYPE_COUNT));
		rv->Assign(1, new Val(ntohl(esp[1]), TYPE_COUNT));
		}
		break;

	default:
		break;
	}

	return rv;
	}

RecordVal* IP_Hdr::BuildIPHdrVal() const
	{
	RecordVal* rval = 0;

	if ( ip4 )
		{
		rval = new RecordVal(hdrType(ip4_hdr_type, "ip4_hdr"));
		rval->Assign(0, new Val(ip4->ip_hl * 4, TYPE_COUNT));
		rval->Assign(1, new Val(ip4->ip_tos, TYPE_COUNT));
		rval->Assign(2, new Val(ntohs(ip4->ip_len), TYPE_COUNT));
		rval->Assign(3, new Val(ntohs(ip4->ip_id), TYPE_COUNT));
		rval->Assign(4, new Val(ip4->ip_ttl, TYPE_COUNT));
		rval->Assign(5, new Val(ip4->ip_p, TYPE_COUNT));
		rval->Assign(6, new AddrVal(ip4->ip_src.s_addr));
		rval->Assign(7, new AddrVal(ip4->ip_dst.s_addr));
		}
	else
		{
		rval = ((*ip6_hdrs)[0])->BuildRecordVal(ip6_hdrs->BuildVal());
		}

	return rval;
	}

RecordVal* IP_Hdr::BuildPktHdrVal() const
	{
	static RecordType* pkt_hdr_type = 0;
	static RecordType* tcp_hdr_type = 0;
	static RecordType* udp_hdr_type = 0;
	static RecordType* icmp_hdr_type = 0;

	if ( ! pkt_hdr_type )
		{
		pkt_hdr_type = internal_type("pkt_hdr")->AsRecordType();
		tcp_hdr_type = internal_type("tcp_hdr")->AsRecordType();
		udp_hdr_type = internal_type("udp_hdr")->AsRecordType();
		icmp_hdr_type = internal_type("icmp_hdr")->AsRecordType();
		}

	RecordVal* pkt_hdr = new RecordVal(pkt_hdr_type);

	if ( ip4 )
		pkt_hdr->Assign(0, BuildIPHdrVal());
	else
		pkt_hdr->Assign(1, BuildIPHdrVal());

	// L4 header.
	const u_char* data = Payload();

	int proto = NextProto();
	switch ( proto ) {
	case IPPROTO_TCP:
		{
		const struct tcphdr* tp = (const struct tcphdr*) data;
		RecordVal* tcp_hdr = new RecordVal(tcp_hdr_type);

		int tcp_hdr_len = tp->th_off * 4;
		int data_len = PayloadLen() - tcp_hdr_len;

		tcp_hdr->Assign(0, new PortVal(ntohs(tp->th_sport), TRANSPORT_TCP));
		tcp_hdr->Assign(1, new PortVal(ntohs(tp->th_dport), TRANSPORT_TCP));
		tcp_hdr->Assign(2, new Val(uint32(ntohl(tp->th_seq)), TYPE_COUNT));
		tcp_hdr->Assign(3, new Val(uint32(ntohl(tp->th_ack)), TYPE_COUNT));
		tcp_hdr->Assign(4, new Val(tcp_hdr_len, TYPE_COUNT));
		tcp_hdr->Assign(5, new Val(data_len, TYPE_COUNT));
		tcp_hdr->Assign(6, new Val(tp->th_flags, TYPE_COUNT));
		tcp_hdr->Assign(7, new Val(ntohs(tp->th_win), TYPE_COUNT));

		pkt_hdr->Assign(2, tcp_hdr);
		break;
		}

	case IPPROTO_UDP:
		{
		const struct udphdr* up = (const struct udphdr*) data;
		RecordVal* udp_hdr = new RecordVal(udp_hdr_type);

		udp_hdr->Assign(0, new PortVal(ntohs(up->uh_sport), TRANSPORT_UDP));
		udp_hdr->Assign(1, new PortVal(ntohs(up->uh_dport), TRANSPORT_UDP));
		udp_hdr->Assign(2, new Val(ntohs(up->uh_ulen), TYPE_COUNT));

		pkt_hdr->Assign(3, udp_hdr);
		break;
		}

	case IPPROTO_ICMP:
		{
		const struct icmp* icmpp = (const struct icmp *) data;
		RecordVal* icmp_hdr = new RecordVal(icmp_hdr_type);

		icmp_hdr->Assign(0, new Val(icmpp->icmp_type, TYPE_COUNT));

		pkt_hdr->Assign(4, icmp_hdr);
		break;
		}

	default:
		{
		// This is not a protocol we understand.
		break;
		}
	}

	return pkt_hdr;
	}

static inline bool isIPv6ExtHeader(uint8 type)
	{
	switch (type) {
	case IPPROTO_HOPOPTS:
	case IPPROTO_ROUTING:
	case IPPROTO_DSTOPTS:
	case IPPROTO_FRAGMENT:
	case IPPROTO_AH:
	case IPPROTO_ESP:
		return true;
	default:
		return false;
	}
	}

void IPv6_Hdr_Chain::Init(const struct ip6_hdr* ip6, bool set_next, uint16 next)
	{
	length = 0;
	uint8 current_type, next_type;
	next_type = IPPROTO_IPV6;
	const u_char* hdrs = (const u_char*) ip6;

	do
		{
		current_type = next_type;
		IPv6_Hdr* p = new IPv6_Hdr(current_type, hdrs);

		next_type = p->NextHdr();
		uint16 len = p->Length();

		if ( set_next && next_type == IPPROTO_FRAGMENT )
			{
			p->ChangeNext(next);
			next_type = next;
			}

		chain.push_back(p);

		// RFC 5095 deprecates routing type 0 headers, so raise weirds for that.
		if ( current_type == IPPROTO_ROUTING &&
		     ((const struct ip6_rthdr*)hdrs)->ip6r_type == 0 )
			{
			IPAddr src(((const struct ip6_hdr*)(chain[0]->Data()))->ip6_src);

			if ( ((const struct ip6_rthdr*)hdrs)->ip6r_segleft > 0 )
				{
				const in6_addr* a = (const in6_addr*)(hdrs+len-16);
				reporter->Weird(src, *a, "routing0_segleft");
				}
			else
				{
				IPAddr dst(((const struct ip6_hdr*)(chain[0]->Data()))->ip6_dst);
				reporter->Weird(src, dst, "routing0_header");
				}
			}

		hdrs += len;
		length += len;
		} while ( current_type != IPPROTO_FRAGMENT &&
				  current_type != IPPROTO_ESP &&
				  isIPv6ExtHeader(next_type) );
	}

VectorVal* IPv6_Hdr_Chain::BuildVal() const
	{
	if ( ! ip6_ext_hdr_type )
		{
		ip6_ext_hdr_type = internal_type("ip6_ext_hdr")->AsRecordType();
		ip6_hopopts_type = internal_type("ip6_hopopts")->AsRecordType();
		ip6_dstopts_type = internal_type("ip6_dstopts")->AsRecordType();
		ip6_routing_type = internal_type("ip6_routing")->AsRecordType();
		ip6_fragment_type = internal_type("ip6_fragment")->AsRecordType();
		ip6_ah_type = internal_type("ip6_ah")->AsRecordType();
		ip6_esp_type = internal_type("ip6_esp")->AsRecordType();
		}

	VectorVal* rval = new VectorVal(new VectorType(ip6_ext_hdr_type->Ref()));

	for ( size_t i = 1; i < chain.size(); ++i )
		{
		RecordVal* v = chain[i]->BuildRecordVal();
		RecordVal* ext_hdr = new RecordVal(ip6_ext_hdr_type);
		uint8 type = chain[i]->Type();
		ext_hdr->Assign(0, new Val(type, TYPE_COUNT));

		switch (type) {
		case IPPROTO_HOPOPTS:
			ext_hdr->Assign(1, v);
			break;
		case IPPROTO_DSTOPTS:
			ext_hdr->Assign(2, v);
			break;
		case IPPROTO_ROUTING:
			ext_hdr->Assign(3, v);
			break;
		case IPPROTO_FRAGMENT:
			ext_hdr->Assign(4, v);
			break;
		case IPPROTO_AH:
			ext_hdr->Assign(5, v);
			break;
		case IPPROTO_ESP:
			ext_hdr->Assign(6, v);
			break;
		default:
			reporter->InternalError("IPv6_Hdr_Chain bad header %d", type);
			break;
		}
		rval->Assign(rval->Size(), ext_hdr, 0);
		}

	return rval;
	}
