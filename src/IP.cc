// See the file "COPYING" in the main distribution directory for copyright.

#include "IP.h"
#include "Type.h"
#include "Val.h"
#include "Var.h"

static RecordType* ip_hdr_type = 0;
static RecordType* ip6_hdr_type = 0;
static RecordType* ip6_hdr_chain_type = 0;
static RecordType* ip6_option_type = 0;
static RecordType* ip6_hopopts_type = 0;
static RecordType* ip6_dstopts_type = 0;
static RecordType* ip6_routing_type = 0;
static RecordType* ip6_fragment_type = 0;
static RecordType* ip6_ah_type = 0;
static RecordType* ip6_esp_type = 0;

static inline RecordType* hdrType(RecordType*& type, const char* name)
	{
	if ( ! type ) type = internal_type(name)->AsRecordType();
	return type;
	}

RecordVal* IPv6_Hdr::BuildRecordVal() const
	{
	RecordVal* rv = new RecordVal(hdrType(ip6_hdr_type, "ip6_hdr"));
	const struct ip6_hdr* ip6 = (const struct ip6_hdr*)data;
	rv->Assign(0, new Val((ntohl(ip6->ip6_flow) & 0x0ff00000)>>20, TYPE_COUNT));
	rv->Assign(1, new Val(ntohl(ip6->ip6_flow) & 0x000fffff, TYPE_COUNT));
	rv->Assign(2, new Val(ntohs(ip6->ip6_plen), TYPE_COUNT));
	rv->Assign(3, new Val(ip6->ip6_nxt, TYPE_COUNT));
	rv->Assign(4, new Val(ip6->ip6_hlim, TYPE_COUNT));
	rv->Assign(5, new AddrVal(ip6->ip6_src));
	rv->Assign(6, new AddrVal(ip6->ip6_dst));
	return rv;
	}

static VectorVal* BuildOptionsVal(const u_char* data, uint16 len)
	{
	VectorVal* vv = new VectorVal(new VectorType(ip6_option_type->Ref()));
	while ( len > 0 )
		{
		const struct ip6_opt* opt = (const struct ip6_opt*) data;
		RecordVal* rv = new RecordVal(hdrType(ip6_option_type, "ip6_option"));
		rv->Assign(0, new Val(opt->ip6o_type, TYPE_COUNT));
		rv->Assign(1, new Val(opt->ip6o_len, TYPE_COUNT));
		uint16 off = 2 * sizeof(uint8);
		rv->Assign(2, new StringVal(
		        new BroString(data + off, opt->ip6o_len - off, 1)));
		data += opt->ip6o_len + off;
		len -= opt->ip6o_len + off;
		vv->Assign(vv->Size(), rv, 0);
		}
	return vv;
	}

RecordVal* IPv6_HopOpts::BuildRecordVal() const
	{
	RecordVal* rv = new RecordVal(hdrType(ip6_hopopts_type, "ip6_hopopts"));
	const struct ip6_hbh* hbh = (const struct ip6_hbh*)data;
	rv->Assign(0, new Val(hbh->ip6h_nxt, TYPE_COUNT));
	rv->Assign(1, new Val(hbh->ip6h_len, TYPE_COUNT));
	uint16 off = 2 * sizeof(uint8);
	rv->Assign(2, BuildOptionsVal(data + off, Length() - off));
	return rv;
	}

RecordVal* IPv6_DstOpts::BuildRecordVal() const
	{
	RecordVal* rv = new RecordVal(hdrType(ip6_dstopts_type, "ip6_dstopts"));
	const struct ip6_dest* dst = (const struct ip6_dest*)data;
	rv->Assign(0, new Val(dst->ip6d_nxt, TYPE_COUNT));
	rv->Assign(1, new Val(dst->ip6d_len, TYPE_COUNT));
	uint16 off = 2 * sizeof(uint8);
	rv->Assign(2, BuildOptionsVal(data + off, Length() - off));
	return rv;
	}

RecordVal* IPv6_Routing::BuildRecordVal() const
	{
	RecordVal* rv = new RecordVal(hdrType(ip6_routing_type, "ip6_routing"));
	const struct ip6_rthdr* rt = (const struct ip6_rthdr*)data;
	rv->Assign(0, new Val(rt->ip6r_nxt, TYPE_COUNT));
	rv->Assign(1, new Val(rt->ip6r_len, TYPE_COUNT));
	rv->Assign(2, new Val(rt->ip6r_type, TYPE_COUNT));
	rv->Assign(3, new Val(rt->ip6r_segleft, TYPE_COUNT));
	uint16 off = 4 * sizeof(uint8);
	rv->Assign(4, new StringVal(new BroString(data + off, Length() - off, 1)));
	return rv;
	}

RecordVal* IPv6_Fragment::BuildRecordVal() const
	{
	RecordVal* rv = new RecordVal(hdrType(ip6_fragment_type, "ip6_fragment"));
	const struct ip6_frag* frag = (const struct ip6_frag*)data;
	rv->Assign(0, new Val(frag->ip6f_nxt, TYPE_COUNT));
	rv->Assign(1, new Val(frag->ip6f_reserved, TYPE_COUNT));
	rv->Assign(2, new Val((ntohs(frag->ip6f_offlg) & 0xfff8)>>3, TYPE_COUNT));
	rv->Assign(3, new Val((ntohs(frag->ip6f_offlg) & 0x0006)>>1, TYPE_COUNT));
	rv->Assign(4, new Val(ntohs(frag->ip6f_offlg) & 0x0001, TYPE_BOOL));
	rv->Assign(5, new Val(ntohl(frag->ip6f_ident), TYPE_COUNT));
	return rv;
	}

RecordVal* IPv6_AH::BuildRecordVal() const
	{
	RecordVal* rv = new RecordVal(hdrType(ip6_ah_type, "ip6_ah"));
	rv->Assign(0, new Val(((ip6_ext*)data)->ip6e_nxt, TYPE_COUNT));
	rv->Assign(1, new Val(((ip6_ext*)data)->ip6e_len, TYPE_COUNT));
	rv->Assign(2, new Val(ntohs(((uint16*)data)[1]), TYPE_COUNT));
	rv->Assign(3, new Val(ntohl(((uint32*)data)[1]), TYPE_COUNT));
	rv->Assign(4, new Val(ntohl(((uint32*)data)[2]), TYPE_COUNT));
	uint16 off = 3 * sizeof(uint32);
	rv->Assign(5, new StringVal(new BroString(data + off, Length() - off, 1)));
	return rv;
	}

RecordVal* IPv6_ESP::BuildRecordVal() const
	{
	RecordVal* rv = new RecordVal(hdrType(ip6_esp_type, "ip6_esp"));
	const uint32* esp = (const uint32*)data;
	rv->Assign(0, new Val(ntohl(esp[0]), TYPE_COUNT));
	rv->Assign(1, new Val(ntohl(esp[1]), TYPE_COUNT));
	return rv;
	}

RecordVal* IP_Hdr::BuildRecordVal() const
	{
	RecordVal* rval = 0;

	if ( ! ip_hdr_type )
		{
		ip_hdr_type = internal_type("ip_hdr")->AsRecordType();
		ip6_hdr_type = internal_type("ip6_hdr")->AsRecordType();
		ip6_hdr_chain_type = internal_type("ip6_hdr_chain")->AsRecordType();
		ip6_hopopts_type = internal_type("ip6_hopopts")->AsRecordType();
		ip6_dstopts_type = internal_type("ip6_dstopts")->AsRecordType();
		ip6_routing_type = internal_type("ip6_routing")->AsRecordType();
		ip6_fragment_type = internal_type("ip6_fragment")->AsRecordType();
		ip6_ah_type = internal_type("ip6_ah")->AsRecordType();
		ip6_esp_type = internal_type("ip6_esp")->AsRecordType();
		}

	if ( ip4 )
		{
		rval = new RecordVal(ip_hdr_type);
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
		rval = new RecordVal(ip6_hdr_chain_type);

		VectorVal* hopopts = new VectorVal(new VectorType(ip6_hopopts_type->Ref()));
		VectorVal* dstopts = new VectorVal(new VectorType(ip6_dstopts_type->Ref()));
		VectorVal* routing = new VectorVal(new VectorType(ip6_routing_type->Ref()));
		VectorVal* fragment = new VectorVal(new VectorType(ip6_fragment_type->Ref()));
		VectorVal* ah = new VectorVal(new VectorType(ip6_ah_type->Ref()));
		VectorVal* esp = new VectorVal(new VectorType(ip6_esp_type->Ref()));
		VectorVal* order = new VectorVal(new VectorType(base_type(TYPE_COUNT)));

		for ( size_t i = 1; i < ip6_hdrs->Size(); ++i )
			{
			RecordVal* v = ((*ip6_hdrs)[i])->BuildRecordVal();
			uint8 type = ((*ip6_hdrs)[i])->Type();
			switch (type) {
			case IPPROTO_HOPOPTS:
				hopopts->Assign(hopopts->Size(), v, 0);
				break;
			case IPPROTO_ROUTING:
				routing->Assign(routing->Size(), v, 0);
				break;
			case IPPROTO_DSTOPTS:
				dstopts->Assign(dstopts->Size(), v, 0);
				break;
			case IPPROTO_FRAGMENT:
				fragment->Assign(fragment->Size(), v, 0);
				break;
			case IPPROTO_AH:
				ah->Assign(ah->Size(), v, 0);
				break;
			case IPPROTO_ESP:
				esp->Assign(esp->Size(), v, 0);
				break;
			case IPPROTO_IPV6:
			default:
				reporter->InternalError("pkt_hdr assigned bad header %d", type);
				break;
			}
			order->Assign(i, new Val(type, TYPE_COUNT), 0);
			}

		rval->Assign(0, ((*ip6_hdrs)[0])->BuildRecordVal());
		rval->Assign(1, hopopts);
		rval->Assign(2, dstopts);
		rval->Assign(3, routing);
		rval->Assign(4, fragment);
		rval->Assign(5, ah);
		rval->Assign(6, esp);
		rval->Assign(7, order);
		}

	return rval;
	}

static inline IPv6_Hdr* getIPv6Header(uint8 type, const u_char* d,
                                      bool set_next = false, uint16 nxt = 0)
	{
	switch (type) {
	case IPPROTO_IPV6:
		return set_next ? new IPv6_Hdr(d, nxt) : new IPv6_Hdr(d);
	case IPPROTO_HOPOPTS:
		return set_next ? new IPv6_HopOpts(d, nxt) : new IPv6_HopOpts(d);
	case IPPROTO_ROUTING:
		return set_next ? new IPv6_Routing(d, nxt) : new IPv6_Routing(d);
	case IPPROTO_DSTOPTS:
		return set_next ? new IPv6_DstOpts(d, nxt) : new IPv6_DstOpts(d);
	case IPPROTO_FRAGMENT:
		return set_next ? new IPv6_Fragment(d, nxt) : new IPv6_Fragment(d);
	case IPPROTO_AH:
		return set_next ? new IPv6_AH(d, nxt) : new IPv6_AH(d);
	case IPPROTO_ESP:
		return new IPv6_ESP(d); // never able to set ESP header's next
	default:
		// should never get here if calls are protected by isIPv6ExtHeader()
		reporter->InternalError("Unknown IPv6 header type: %d", type);
		break;
	}
	// can't be reached
	assert(false);
	return 0;
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
		chain.push_back(getIPv6Header(current_type, hdrs, set_next, next));
		next_type = chain[chain.size()-1]->NextHdr();
		uint16 len = chain[chain.size()-1]->Length();
		hdrs += len;
		length += len;
		} while ( current_type != IPPROTO_FRAGMENT &&
				  current_type != IPPROTO_ESP &&
				  isIPv6ExtHeader(next_type) );
	}
