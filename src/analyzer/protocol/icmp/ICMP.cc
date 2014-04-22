// See the file "COPYING" in the main distribution directory for copyright.

#include <algorithm>

#include "config.h"

#include "Net.h"
#include "NetVar.h"
#include "Event.h"
#include "ICMP.h"
#include "Conn.h"

#include "events.bif.h"

#include <netinet/icmp6.h>

using namespace analyzer::icmp;

ICMP_Analyzer::ICMP_Analyzer(Connection* c)
	: TransportLayerAnalyzer("ICMP", c),
	icmp_conn_val(), type(), code(), request_len(-1), reply_len(-1)
	{
	c->SetInactivityTimeout(icmp_inactivity_timeout);
	}

void ICMP_Analyzer::Done()
	{
	TransportLayerAnalyzer::Done();
	Unref(icmp_conn_val);
	matcher_state.FinishEndpointMatcher();
	}

void ICMP_Analyzer::DeliverPacket(int len, const u_char* data,
			bool is_orig, int seq, const IP_Hdr* ip, int caplen)
	{
	assert(ip);

	TransportLayerAnalyzer::DeliverPacket(len, data, is_orig, seq, ip, caplen);

	// We need the min() here because Ethernet frame padding can lead to
	// caplen > len.
	if ( packet_contents )
		// Subtract off the common part of ICMP header.
		PacketContents(data + 8, min(len, caplen) - 8);

	const struct icmp* icmpp = (const struct icmp*) data;

	if ( ! ignore_checksums && caplen >= len )
		{
		int chksum = 0;

		switch ( ip->NextProto() )
		{
		case IPPROTO_ICMP:
			chksum = icmp_checksum(icmpp, len);
			break;

		case IPPROTO_ICMPV6:
			chksum = icmp6_checksum(icmpp, ip, len);
			break;

		default:
			reporter->AnalyzerError(this,
			  "unexpected IP proto in ICMP analyzer: %d", ip->NextProto());
			return;
		}

		if ( chksum != 0xffff )
			{
			Weird("bad_ICMP_checksum");
			return;
			}
		}

	Conn()->SetLastTime(current_timestamp);

	if ( rule_matcher )
		{
		if ( ! matcher_state.MatcherInitialized(is_orig) )
			matcher_state.InitEndpointMatcher(this, ip, len, is_orig, 0);
		}

	type = icmpp->icmp_type;
	code = icmpp->icmp_code;

	// Move past common portion of ICMP header.
	data += 8;
	caplen -= 8;
	len -= 8;

	int& len_stat = is_orig ? request_len : reply_len;
	if ( len_stat < 0 )
		len_stat = len;
	else
		len_stat += len;

	if ( ip->NextProto() == IPPROTO_ICMP )
		NextICMP4(current_timestamp, icmpp, len, caplen, data, ip);
	else if ( ip->NextProto() == IPPROTO_ICMPV6 )
		NextICMP6(current_timestamp, icmpp, len, caplen, data, ip);
	else
		{
		reporter->AnalyzerError(this,
		  "expected ICMP as IP packet's protocol, got %d", ip->NextProto());
		return;
		}


	if ( caplen >= len )
		ForwardPacket(len, data, is_orig, seq, ip, caplen);

	if ( rule_matcher )
		matcher_state.Match(Rule::PAYLOAD, data, len, is_orig,
					false, false, true);
	}

void ICMP_Analyzer::NextICMP4(double t, const struct icmp* icmpp, int len, int caplen,
		const u_char*& data, const IP_Hdr* ip_hdr )
	{
	switch ( icmpp->icmp_type )
		{
		case ICMP_ECHO:
		case ICMP_ECHOREPLY:
			Echo(t, icmpp, len, caplen, data, ip_hdr);
			break;

		case ICMP_UNREACH:
		case ICMP_TIMXCEED:
			Context4(t, icmpp, len, caplen, data, ip_hdr);
			break;

		default:
			ICMPEvent(icmp_sent, icmpp, len, 0, ip_hdr);
			break;
		}
	}

void ICMP_Analyzer::NextICMP6(double t, const struct icmp* icmpp, int len, int caplen,
							  const u_char*& data, const IP_Hdr* ip_hdr )
	{
	switch ( icmpp->icmp_type )
		{
		// Echo types.
		case ICMP6_ECHO_REQUEST:
		case ICMP6_ECHO_REPLY:
			Echo(t, icmpp, len, caplen, data, ip_hdr);
			break;

		// Error messages all have the same structure for their context,
		// and are handled by the same function.
		case ICMP6_PARAM_PROB:
		case ICMP6_TIME_EXCEEDED:
		case ICMP6_PACKET_TOO_BIG:
		case ICMP6_DST_UNREACH:
			Context6(t, icmpp, len, caplen, data, ip_hdr);
			break;

		// Router related messages.
		case ND_REDIRECT:
			Redirect(t, icmpp, len, caplen, data, ip_hdr);
			break;
		case ND_ROUTER_ADVERT:
			RouterAdvert(t, icmpp, len, caplen, data, ip_hdr);
			break;
		case ND_NEIGHBOR_ADVERT:
			NeighborAdvert(t, icmpp, len, caplen, data, ip_hdr);
			break;
		case ND_NEIGHBOR_SOLICIT:
			NeighborSolicit(t, icmpp, len, caplen, data, ip_hdr);
			break;
		case ND_ROUTER_SOLICIT:
			RouterSolicit(t, icmpp, len, caplen, data, ip_hdr);
			break;
		case ICMP6_ROUTER_RENUMBERING:
			ICMPEvent(icmp_sent, icmpp, len, 1, ip_hdr);
			break;

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
				Context6(t, icmpp, len, caplen, data, ip_hdr);
			else
				ICMPEvent(icmp_sent, icmpp, len, 1, ip_hdr);
			break;
		}
	}

void ICMP_Analyzer::ICMPEvent(EventHandlerPtr f, const struct icmp* icmpp,
                              int len, int icmpv6, const IP_Hdr* ip_hdr)
    {
	if ( ! f )
		return;

	val_list* vl = new val_list;
	vl->append(BuildConnVal());
	vl->append(BuildICMPVal(icmpp, len, icmpv6, ip_hdr));
	ConnectionEvent(f, vl);
	}

RecordVal* ICMP_Analyzer::BuildICMPVal(const struct icmp* icmpp, int len,
                                       int icmpv6, const IP_Hdr* ip_hdr)
	{
	if ( ! icmp_conn_val )
		{
		icmp_conn_val = new RecordVal(icmp_conn);

		icmp_conn_val->Assign(0, new AddrVal(Conn()->OrigAddr()));
		icmp_conn_val->Assign(1, new AddrVal(Conn()->RespAddr()));
		icmp_conn_val->Assign(2, new Val(icmpp->icmp_type, TYPE_COUNT));
		icmp_conn_val->Assign(3, new Val(icmpp->icmp_code, TYPE_COUNT));
		icmp_conn_val->Assign(4, new Val(len, TYPE_COUNT));
		icmp_conn_val->Assign(5, new Val(ip_hdr->TTL(), TYPE_COUNT));
		icmp_conn_val->Assign(6, new Val(icmpv6, TYPE_BOOL));
		}

	Ref(icmp_conn_val);

	return icmp_conn_val;
	}

TransportProto ICMP_Analyzer::GetContextProtocol(const IP_Hdr* ip_hdr, uint32* src_port, uint32* dst_port)
	{
	const u_char* transport_hdr;
	uint32 ip_hdr_len = ip_hdr->HdrLen();
	bool ip4 = ip_hdr->IP4_Hdr();

	if ( ip4 )
		transport_hdr = ((u_char *) ip_hdr->IP4_Hdr() + ip_hdr_len);
	else
		transport_hdr = ((u_char *) ip_hdr->IP6_Hdr() + ip_hdr_len);

	TransportProto proto;

	switch ( ip_hdr->NextProto() ) {
	case 1:		proto = TRANSPORT_ICMP; break;
	case 6:		proto = TRANSPORT_TCP; break;
	case 17:	proto = TRANSPORT_UDP; break;
	case 58:	proto = TRANSPORT_ICMP; break;
	default:	proto = TRANSPORT_UNKNOWN; break;
	}

	switch ( proto ) {
	case TRANSPORT_ICMP:
		{
		const struct icmp* icmpp =
			(const struct icmp *) transport_hdr;
		bool is_one_way;	// dummy
		*src_port = ntohs(icmpp->icmp_type);

		if ( ip4 )
			*dst_port = ntohs(ICMP4_counterpart(icmpp->icmp_type,
					icmpp->icmp_code, is_one_way));
		else
			*dst_port = ntohs(ICMP6_counterpart(icmpp->icmp_type,
					icmpp->icmp_code, is_one_way));

		break;
		}

	case TRANSPORT_TCP:
		{
		const struct tcphdr* tp =
			(const struct tcphdr *) transport_hdr;
		*src_port = ntohs(tp->th_sport);
		*dst_port = ntohs(tp->th_dport);
		break;
		}

	case TRANSPORT_UDP:
		{
		const struct udphdr* up =
			(const struct udphdr *) transport_hdr;
		*src_port = ntohs(up->uh_sport);
		*dst_port = ntohs(up->uh_dport);
		break;
		}

	default:
		*src_port = *dst_port = ntohs(0);
		break;
	}

	return proto;
	}

RecordVal* ICMP_Analyzer::ExtractICMP4Context(int len, const u_char*& data)
	{
	const IP_Hdr ip_hdr_data((const struct ip*) data, false);
	const IP_Hdr* ip_hdr = &ip_hdr_data;

	uint32 ip_hdr_len = ip_hdr->HdrLen();

	uint32 ip_len, frag_offset;
	TransportProto proto = TRANSPORT_UNKNOWN;
	int DF, MF, bad_hdr_len, bad_checksum;
	IPAddr src_addr, dst_addr;
	uint32 src_port, dst_port;

	if ( len < (int)sizeof(struct ip) || ip_hdr_len > uint32(len) )
		{
		// We don't have an entire IP header.
		bad_hdr_len = 1;
		ip_len = frag_offset = 0;
		DF = MF = bad_checksum = 0;
		src_port = dst_port = 0;
		}

	else
		{
		bad_hdr_len = 0;
		ip_len = ip_hdr->TotalLen();
		bad_checksum = (ones_complement_checksum((void*) ip_hdr->IP4_Hdr(), ip_hdr_len, 0) != 0xffff);

		src_addr = ip_hdr->SrcAddr();
		dst_addr = ip_hdr->DstAddr();

		DF = ip_hdr->DF();
		MF = ip_hdr->MF();
		frag_offset = ip_hdr->FragOffset();

		if ( uint32(len) >= ip_hdr_len + 4 )
			proto = GetContextProtocol(ip_hdr, &src_port, &dst_port);
		else
			{
			// 4 above is the magic number meaning that both
			// port numbers are included in the ICMP.
			src_port = dst_port = 0;
			bad_hdr_len = 1;
			}
		}

	RecordVal* iprec = new RecordVal(icmp_context);
	RecordVal* id_val = new RecordVal(conn_id);

	id_val->Assign(0, new AddrVal(src_addr));
	id_val->Assign(1, new PortVal(src_port, proto));
	id_val->Assign(2, new AddrVal(dst_addr));
	id_val->Assign(3, new PortVal(dst_port, proto));

	iprec->Assign(0, id_val);
	iprec->Assign(1, new Val(ip_len, TYPE_COUNT));
	iprec->Assign(2, new Val(proto, TYPE_COUNT));
	iprec->Assign(3, new Val(frag_offset, TYPE_COUNT));
	iprec->Assign(4, new Val(bad_hdr_len, TYPE_BOOL));
	iprec->Assign(5, new Val(bad_checksum, TYPE_BOOL));
	iprec->Assign(6, new Val(MF, TYPE_BOOL));
	iprec->Assign(7, new Val(DF, TYPE_BOOL));

	return iprec;
	}

RecordVal* ICMP_Analyzer::ExtractICMP6Context(int len, const u_char*& data)
	{
	int DF = 0, MF = 0, bad_hdr_len = 0;
	TransportProto proto = TRANSPORT_UNKNOWN;

	IPAddr src_addr;
	IPAddr dst_addr;
	uint32 ip_len, frag_offset = 0;
	uint32 src_port, dst_port;

	if ( len < (int)sizeof(struct ip6_hdr) )
		{
		bad_hdr_len = 1;
		ip_len = 0;
		src_port = dst_port = 0;
		}
	else
		{
		const IP_Hdr ip_hdr_data((const struct ip6_hdr*) data, false, len);
		const IP_Hdr* ip_hdr = &ip_hdr_data;

		ip_len = ip_hdr->TotalLen();
		src_addr = ip_hdr->SrcAddr();
		dst_addr = ip_hdr->DstAddr();
		frag_offset = ip_hdr->FragOffset();
		MF = ip_hdr->MF();
		DF = ip_hdr->DF();

		if ( uint32(len) >= uint32(ip_hdr->HdrLen() + 4) )
			proto = GetContextProtocol(ip_hdr, &src_port, &dst_port);
		else
			{
			// 4 above is the magic number meaning that both
			// port numbers are included in the ICMP.
			src_port = dst_port = 0;
			bad_hdr_len = 1;
			}
		}

	RecordVal* iprec = new RecordVal(icmp_context);
	RecordVal* id_val = new RecordVal(conn_id);

	id_val->Assign(0, new AddrVal(src_addr));
	id_val->Assign(1, new PortVal(src_port, proto));
	id_val->Assign(2, new AddrVal(dst_addr));
	id_val->Assign(3, new PortVal(dst_port, proto));

	iprec->Assign(0, id_val);
	iprec->Assign(1, new Val(ip_len, TYPE_COUNT));
	iprec->Assign(2, new Val(proto, TYPE_COUNT));
	iprec->Assign(3, new Val(frag_offset, TYPE_COUNT));
	iprec->Assign(4, new Val(bad_hdr_len, TYPE_BOOL));
	// bad_checksum is always false since IPv6 layer doesn't have a checksum.
	iprec->Assign(5, new Val(0, TYPE_BOOL));
	iprec->Assign(6, new Val(MF, TYPE_BOOL));
	iprec->Assign(7, new Val(DF, TYPE_BOOL));

	return iprec;
	}

bool ICMP_Analyzer::IsReuse(double /* t */, const u_char* /* pkt */)
	{
	return 0;
	}

void ICMP_Analyzer::Describe(ODesc* d) const
	{
	d->Add(Conn()->StartTime());
	d->Add("(");
	d->Add(Conn()->LastTime());
	d->AddSP(")");

	d->Add(Conn()->OrigAddr());
	d->Add(".");
	d->Add(type);
	d->Add(".");
	d->Add(code);

	d->SP();
	d->AddSP("->");

	d->Add(Conn()->RespAddr());
	}

void ICMP_Analyzer::UpdateConnVal(RecordVal *conn_val)
	{
	RecordVal *orig_endp = conn_val->Lookup("orig")->AsRecordVal();
	RecordVal *resp_endp = conn_val->Lookup("resp")->AsRecordVal();

	UpdateEndpointVal(orig_endp, 1);
	UpdateEndpointVal(resp_endp, 0);

	// Call children's UpdateConnVal
	Analyzer::UpdateConnVal(conn_val);
	}

void ICMP_Analyzer::UpdateEndpointVal(RecordVal* endp, int is_orig)
	{
	Conn()->EnableStatusUpdateTimer();

	int size = is_orig ? request_len : reply_len;
	if ( size < 0 )
		{
		endp->Assign(0, new Val(0, TYPE_COUNT));
		endp->Assign(1, new Val(int(ICMP_INACTIVE), TYPE_COUNT));
		}

	else
		{
		endp->Assign(0, new Val(size, TYPE_COUNT));
		endp->Assign(1, new Val(int(ICMP_ACTIVE), TYPE_COUNT));
		}
	}

unsigned int ICMP_Analyzer::MemoryAllocation() const
	{
	return Analyzer::MemoryAllocation()
		+ padded_sizeof(*this) - padded_sizeof(Connection)
		+ (icmp_conn_val ? icmp_conn_val->MemoryAllocation() : 0);
	}


void ICMP_Analyzer::Echo(double t, const struct icmp* icmpp, int len,
					 int caplen, const u_char*& data, const IP_Hdr* ip_hdr)
	{
	// For handling all Echo related ICMP messages
	EventHandlerPtr f = 0;

	if ( ip_hdr->NextProto() == IPPROTO_ICMPV6 )
		f = (icmpp->icmp_type == ICMP6_ECHO_REQUEST)
			? icmp_echo_request : icmp_echo_reply;
	else
		f = (icmpp->icmp_type == ICMP_ECHO)
			? icmp_echo_request : icmp_echo_reply;

	if ( ! f )
		return;

	int iid = ntohs(icmpp->icmp_hun.ih_idseq.icd_id);
	int iseq = ntohs(icmpp->icmp_hun.ih_idseq.icd_seq);

	BroString* payload = new BroString(data, caplen, 0);

	val_list* vl = new val_list;
	vl->append(BuildConnVal());
	vl->append(BuildICMPVal(icmpp, len, ip_hdr->NextProto() != IPPROTO_ICMP, ip_hdr));
	vl->append(new Val(iid, TYPE_COUNT));
	vl->append(new Val(iseq, TYPE_COUNT));
	vl->append(new StringVal(payload));

	ConnectionEvent(f, vl);
	}


void ICMP_Analyzer::RouterAdvert(double t, const struct icmp* icmpp, int len,
			 int caplen, const u_char*& data, const IP_Hdr* ip_hdr)
	{
	EventHandlerPtr f = icmp_router_advertisement;
	uint32 reachable = 0, retrans = 0;

	if ( caplen >= (int)sizeof(reachable) )
		memcpy(&reachable, data, sizeof(reachable));

	if ( caplen >= (int)sizeof(reachable) + (int)sizeof(retrans) )
		memcpy(&retrans, data + sizeof(reachable), sizeof(retrans));

	val_list* vl = new val_list;
	vl->append(BuildConnVal());
	vl->append(BuildICMPVal(icmpp, len, 1, ip_hdr));
	vl->append(new Val(icmpp->icmp_num_addrs, TYPE_COUNT)); // Cur Hop Limit
	vl->append(new Val(icmpp->icmp_wpa & 0x80, TYPE_BOOL)); // Managed
	vl->append(new Val(icmpp->icmp_wpa & 0x40, TYPE_BOOL)); // Other
	vl->append(new Val(icmpp->icmp_wpa & 0x20, TYPE_BOOL)); // Home Agent
	vl->append(new Val((icmpp->icmp_wpa & 0x18)>>3, TYPE_COUNT)); // Pref
	vl->append(new Val(icmpp->icmp_wpa & 0x04, TYPE_BOOL)); // Proxy
	vl->append(new Val(icmpp->icmp_wpa & 0x02, TYPE_COUNT)); // Reserved
	vl->append(new IntervalVal((double)ntohs(icmpp->icmp_lifetime), Seconds));
	vl->append(new IntervalVal((double)ntohl(reachable), Milliseconds));
	vl->append(new IntervalVal((double)ntohl(retrans), Milliseconds));

	int opt_offset = sizeof(reachable) + sizeof(retrans);
	vl->append(BuildNDOptionsVal(caplen - opt_offset, data + opt_offset));

	ConnectionEvent(f, vl);
	}


void ICMP_Analyzer::NeighborAdvert(double t, const struct icmp* icmpp, int len,
			 int caplen, const u_char*& data, const IP_Hdr* ip_hdr)
	{
	EventHandlerPtr f = icmp_neighbor_advertisement;
	IPAddr tgtaddr;

	if ( caplen >= (int)sizeof(in6_addr) )
		tgtaddr = IPAddr(*((const in6_addr*)data));

	val_list* vl = new val_list;
	vl->append(BuildConnVal());
	vl->append(BuildICMPVal(icmpp, len, 1, ip_hdr));
	vl->append(new Val(icmpp->icmp_num_addrs & 0x80, TYPE_BOOL)); // Router
	vl->append(new Val(icmpp->icmp_num_addrs & 0x40, TYPE_BOOL)); // Solicited
	vl->append(new Val(icmpp->icmp_num_addrs & 0x20, TYPE_BOOL)); // Override
	vl->append(new AddrVal(tgtaddr));

	int opt_offset = sizeof(in6_addr);
	vl->append(BuildNDOptionsVal(caplen - opt_offset, data + opt_offset));

	ConnectionEvent(f, vl);
	}


void ICMP_Analyzer::NeighborSolicit(double t, const struct icmp* icmpp, int len,
			 int caplen, const u_char*& data, const IP_Hdr* ip_hdr)
	{
	EventHandlerPtr f = icmp_neighbor_solicitation;
	IPAddr tgtaddr;

	if ( caplen >= (int)sizeof(in6_addr) )
		tgtaddr = IPAddr(*((const in6_addr*)data));

	val_list* vl = new val_list;
	vl->append(BuildConnVal());
	vl->append(BuildICMPVal(icmpp, len, 1, ip_hdr));
	vl->append(new AddrVal(tgtaddr));

	int opt_offset = sizeof(in6_addr);
	vl->append(BuildNDOptionsVal(caplen - opt_offset, data + opt_offset));

	ConnectionEvent(f, vl);
	}


void ICMP_Analyzer::Redirect(double t, const struct icmp* icmpp, int len,
			 int caplen, const u_char*& data, const IP_Hdr* ip_hdr)
	{
	EventHandlerPtr f = icmp_redirect;
	IPAddr tgtaddr, dstaddr;

	if ( caplen >= (int)sizeof(in6_addr) )
		tgtaddr = IPAddr(*((const in6_addr*)data));

	if ( caplen >= 2 * (int)sizeof(in6_addr) )
		dstaddr = IPAddr(*((const in6_addr*)(data + sizeof(in6_addr))));

	val_list* vl = new val_list;
	vl->append(BuildConnVal());
	vl->append(BuildICMPVal(icmpp, len, 1, ip_hdr));
	vl->append(new AddrVal(tgtaddr));
	vl->append(new AddrVal(dstaddr));

	int opt_offset = 2 * sizeof(in6_addr);
	vl->append(BuildNDOptionsVal(caplen - opt_offset, data + opt_offset));

	ConnectionEvent(f, vl);
	}


void ICMP_Analyzer::RouterSolicit(double t, const struct icmp* icmpp, int len,
			 int caplen, const u_char*& data, const IP_Hdr* ip_hdr)
	{
	EventHandlerPtr f = icmp_router_solicitation;

	val_list* vl = new val_list;
	vl->append(BuildConnVal());
	vl->append(BuildICMPVal(icmpp, len, 1, ip_hdr));
	vl->append(BuildNDOptionsVal(caplen, data));

	ConnectionEvent(f, vl);
	}


void ICMP_Analyzer::Context4(double t, const struct icmp* icmpp,
		int len, int caplen, const u_char*& data, const IP_Hdr* ip_hdr)
	{
	EventHandlerPtr f = 0;

	switch ( icmpp->icmp_type )
		{
		case ICMP_UNREACH:
			f = icmp_unreachable;
			break;

		case ICMP_TIMXCEED:
			f = icmp_time_exceeded;
			break;
		}

	if ( f )
		{
		val_list* vl = new val_list;
		vl->append(BuildConnVal());
		vl->append(BuildICMPVal(icmpp, len, 0, ip_hdr));
		vl->append(new Val(icmpp->icmp_code, TYPE_COUNT));
		vl->append(ExtractICMP4Context(caplen, data));
		ConnectionEvent(f, vl);
		}
	}


void ICMP_Analyzer::Context6(double t, const struct icmp* icmpp,
		int len, int caplen, const u_char*& data, const IP_Hdr* ip_hdr)
	{
	EventHandlerPtr f = 0;

	switch ( icmpp->icmp_type )
		{
		case ICMP6_DST_UNREACH:
			f = icmp_unreachable;
			break;

		case ICMP6_PARAM_PROB:
			f = icmp_parameter_problem;
			break;

		case ICMP6_TIME_EXCEEDED:
			f = icmp_time_exceeded;
			break;

		case ICMP6_PACKET_TOO_BIG:
			f = icmp_packet_too_big;
			break;

		default:
			f = icmp_error_message;
			break;
		}

	if ( f )
		{
		val_list* vl = new val_list;
		vl->append(BuildConnVal());
		vl->append(BuildICMPVal(icmpp, len, 1, ip_hdr));
		vl->append(new Val(icmpp->icmp_code, TYPE_COUNT));
		vl->append(ExtractICMP6Context(caplen, data));
		ConnectionEvent(f, vl);
		}
	}

VectorVal* ICMP_Analyzer::BuildNDOptionsVal(int caplen, const u_char* data)
	{
	static RecordType* icmp6_nd_option_type = 0;
	static RecordType* icmp6_nd_prefix_info_type = 0;

	if ( ! icmp6_nd_option_type )
		{
		icmp6_nd_option_type = internal_type("icmp6_nd_option")->AsRecordType();
		icmp6_nd_prefix_info_type =
		        internal_type("icmp6_nd_prefix_info")->AsRecordType();
		}

	VectorVal* vv = new VectorVal(
	        internal_type("icmp6_nd_options")->AsVectorType());

	while ( caplen > 0 )
		{
		// Must have at least type & length to continue parsing options.
		if ( caplen < 2 )
			{
			Weird("truncated_ICMPv6_ND_options");
			break;
			}

		uint8 type = *((const uint8*)data);
		uint8 length = *((const uint8*)(data + 1));

		if ( length == 0 )
			{
			Weird("zero_length_ICMPv6_ND_option");
			break;
			}

		RecordVal* rv = new RecordVal(icmp6_nd_option_type);
		rv->Assign(0, new Val(type, TYPE_COUNT));
		rv->Assign(1, new Val(length, TYPE_COUNT));

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
			if ( caplen >= length )
				{
				BroString* link_addr = new BroString(data, length, 0);
				rv->Assign(2, new StringVal(link_addr));
				}
			else
				set_payload_field = true;

			break;
			}

		case 3:
			// Prefix Information option
			{
			if ( caplen >= 30 )
				{
				RecordVal* info = new RecordVal(icmp6_nd_prefix_info_type);
				uint8 prefix_len = *((const uint8*)(data));
				bool L_flag = (*((const uint8*)(data + 1)) & 0x80) != 0;
				bool A_flag = (*((const uint8*)(data + 1)) & 0x40) != 0;
				uint32 valid_life = *((const uint32*)(data + 2));
				uint32 prefer_life = *((const uint32*)(data + 6));
				in6_addr prefix = *((const in6_addr*)(data + 14));
				info->Assign(0, new Val(prefix_len, TYPE_COUNT));
				info->Assign(1, new Val(L_flag, TYPE_BOOL));
				info->Assign(2, new Val(A_flag, TYPE_BOOL));
				info->Assign(3, new IntervalVal((double)ntohl(valid_life), Seconds));
				info->Assign(4, new IntervalVal((double)ntohl(prefer_life), Seconds));
				info->Assign(5, new AddrVal(IPAddr(prefix)));
				rv->Assign(3, info);
				}

			else
				set_payload_field = true;
			break;
			}

		case 4:
			// Redirected Header option
			{
			if ( caplen >= length )
				{
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
				rv->Assign(5, new Val(ntohl(*((const uint32*)(data + 2))),
				                      TYPE_COUNT));
			else
				set_payload_field = true;

			break;
			}

		default:
			{
			set_payload_field = true;
			break;
			}
		}

		if ( set_payload_field )
			{
			BroString* payload =
			        new BroString(data, min((int)length, caplen), 0);
			rv->Assign(6, new StringVal(payload));
			}

		data += length;
		caplen -= length;

		vv->Assign(vv->Size(), rv);
		}

	return vv;
	}

int analyzer::icmp::ICMP4_counterpart(int icmp_type, int icmp_code, bool& is_one_way)
	{
	is_one_way = false;

	// Return the counterpart type if one exists.  This allows us
	// to track corresponding ICMP requests/replies.
	// Note that for the two-way ICMP messages, icmp_code is
	// always 0 (RFC 792).
	switch ( icmp_type ) {
	case ICMP_ECHO:			return ICMP_ECHOREPLY;
	case ICMP_ECHOREPLY:		return ICMP_ECHO;

	case ICMP_TSTAMP:		return ICMP_TSTAMPREPLY;
	case ICMP_TSTAMPREPLY:		return ICMP_TSTAMP;

	case ICMP_IREQ:			return ICMP_IREQREPLY;
	case ICMP_IREQREPLY:		return ICMP_IREQ;

	case ICMP_ROUTERSOLICIT:	return ICMP_ROUTERADVERT;

	case ICMP_MASKREQ:		return ICMP_MASKREPLY;
	case ICMP_MASKREPLY:		return ICMP_MASKREQ;

	default:			is_one_way = true; return icmp_code;
	}
	}

int analyzer::icmp::ICMP6_counterpart(int icmp_type, int icmp_code, bool& is_one_way)
	{
	is_one_way = false;

	switch ( icmp_type ) {
	case ICMP6_ECHO_REQUEST:		return ICMP6_ECHO_REPLY;
	case ICMP6_ECHO_REPLY:			return ICMP6_ECHO_REQUEST;

	case ND_ROUTER_SOLICIT:			return ND_ROUTER_ADVERT;
	case ND_ROUTER_ADVERT:			return ND_ROUTER_SOLICIT;

	case ND_NEIGHBOR_SOLICIT:		return ND_NEIGHBOR_ADVERT;
	case ND_NEIGHBOR_ADVERT:		return ND_NEIGHBOR_SOLICIT;

	case MLD_LISTENER_QUERY: 		return MLD_LISTENER_REPORT;
	case MLD_LISTENER_REPORT:		return MLD_LISTENER_QUERY;

	// ICMP node information query and response respectively (not defined in
	// icmp6.h)
	case 139:						return 140;
	case 140:						return 139;

	// Home Agent Address Discovery Request Message and reply
	case 144:							return 145;
	case 145:							return 144;

	// TODO: Add further counterparts.

	default:			is_one_way = true; return icmp_code;
	}
	}
