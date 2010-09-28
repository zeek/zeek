// $Id: ICMP.cc 6219 2008-10-01 05:39:07Z vern $
//
// See the file "COPYING" in the main distribution directory for copyright.

#include "config.h"

#include "Net.h"
#include "NetVar.h"
#include "Event.h"
#include "ICMP.h"

ICMP_Analyzer::ICMP_Analyzer(Connection* c)
: TransportLayerAnalyzer(AnalyzerTag::ICMP, c)
	{
	icmp_conn_val = 0;
	c->SetInactivityTimeout(icmp_inactivity_timeout);
	request_len = reply_len = -1;
	}

ICMP_Analyzer::ICMP_Analyzer(AnalyzerTag::Tag tag, Connection* c)
: TransportLayerAnalyzer(tag, c)
	{
	icmp_conn_val = 0;
	c->SetInactivityTimeout(icmp_inactivity_timeout);
	request_len = reply_len = -1;
	}

void ICMP_Analyzer::Done()
	{
	TransportLayerAnalyzer::Done();
	Unref(icmp_conn_val);
	matcher_state.FinishEndpointMatcher();
	}

void ICMP_Analyzer::DeliverPacket(int arg_len, const u_char* data,
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
	len = arg_len;

	if ( ! ignore_checksums && caplen >= len &&
	     icmp_checksum(icmpp, len) != 0xffff )
		{
		Weird("bad_ICMP_checksum");
		return;
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

	NextICMP(current_timestamp, icmpp, len, caplen, data);

	if ( rule_matcher )
		matcher_state.Match(Rule::PAYLOAD, data, len, is_orig,
					false, false, true);
	}

void ICMP_Analyzer::NextICMP(double /* t */, const struct icmp* /* icmpp */,
				int /* len */, int /* caplen */,
				const u_char*& /* data */)
	{
	ICMPEvent(icmp_sent);
	}

void ICMP_Analyzer::ICMPEvent(EventHandlerPtr f)
	{
	if ( ! f )
		return;

	val_list* vl = new val_list;
	vl->append(BuildConnVal());
	vl->append(BuildICMPVal());

	ConnectionEvent(f, vl);
	}

RecordVal* ICMP_Analyzer::BuildICMPVal()
	{
	if ( ! icmp_conn_val )
		{
		icmp_conn_val = new RecordVal(icmp_conn);

		icmp_conn_val->Assign(0, new AddrVal(Conn()->OrigAddr()));
		icmp_conn_val->Assign(1, new AddrVal(Conn()->RespAddr()));
		icmp_conn_val->Assign(2, new Val(type, TYPE_COUNT));
		icmp_conn_val->Assign(3, new Val(code, TYPE_COUNT));
		icmp_conn_val->Assign(4, new Val(len, TYPE_COUNT));
		}

	Ref(icmp_conn_val);

	return icmp_conn_val;
	}

RecordVal* ICMP_Analyzer::ExtractICMPContext(int len, const u_char*& data)
	{
	const struct ip* ip = (const struct ip *) data;
	uint32 ip_hdr_len = ip->ip_hl * 4;

	uint32 ip_len, frag_offset;
	TransportProto proto = TRANSPORT_UNKNOWN;
	int DF, MF, bad_hdr_len, bad_checksum;
	uint32 src_addr, dst_addr;
	uint32 src_port, dst_port;

	if ( ip_hdr_len < sizeof(struct ip) || ip_hdr_len > uint32(len) )
		{ // We don't have an entire IP header.
		bad_hdr_len = 1;
		ip_len = frag_offset = 0;
		DF = MF = bad_checksum = 0;
		src_addr = dst_addr = 0;
		src_port = dst_port = 0;
		}

	else
		{
		bad_hdr_len = 0;
		ip_len = ntohs(ip->ip_len);
		bad_checksum = ones_complement_checksum((void*) ip, ip_hdr_len, 0) != 0xffff;

		src_addr = uint32(ip->ip_src.s_addr);
		dst_addr = uint32(ip->ip_dst.s_addr);

		switch ( ip->ip_p ) {
		case 1:		proto = TRANSPORT_ICMP; break;
		case 6:		proto = TRANSPORT_TCP; break;
		case 17:	proto = TRANSPORT_UDP; break;

		// Default uses TRANSPORT_UNKNOWN, per initialization above.
		}

		uint32 frag_field = ntohs(ip->ip_off);
		DF = frag_field & 0x4000;
		MF = frag_field & 0x2000;
		frag_offset = frag_field & /* IP_OFFMASK not portable */ 0x1fff;
		const u_char* transport_hdr = ((u_char *) ip + ip_hdr_len);

		if ( uint32(len) < ip_hdr_len + 4 )
			{
			// 4 above is the magic number meaning that both
			// port numbers are included in the ICMP.
			bad_hdr_len = 1;
			src_port = dst_port = 0;
			}

		switch ( proto ) {
		case TRANSPORT_ICMP:
			{
			const struct icmp* icmpp =
				(const struct icmp *) transport_hdr;
			bool is_one_way;	// dummy
			src_port = ntohs(icmpp->icmp_type);
			dst_port = ntohs(ICMP_counterpart(icmpp->icmp_type,
							icmpp->icmp_code,
							is_one_way));
			}
			break;

		case TRANSPORT_TCP:
			{
			const struct tcphdr* tp =
				(const struct tcphdr *) transport_hdr;
			src_port = ntohs(tp->th_sport);
			dst_port = ntohs(tp->th_dport);
			}
			break;

		case TRANSPORT_UDP:
			{
			const struct udphdr* up =
				(const struct udphdr *) transport_hdr;
			src_port = ntohs(up->uh_sport);
			dst_port = ntohs(up->uh_dport);
			}
			break;

		default:
			src_port = dst_port = ntohs(0);
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

	d->Add(dotted_addr(Conn()->OrigAddr()));
	d->Add(".");
	d->Add(type);
	d->Add(".");
	d->Add(code);

	d->SP();
	d->AddSP("->");

	d->Add(dotted_addr(Conn()->RespAddr()));
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

ICMP_Echo_Analyzer::ICMP_Echo_Analyzer(Connection* c)
: ICMP_Analyzer(AnalyzerTag::ICMP_Echo, c)
	{
	}

void ICMP_Echo_Analyzer::NextICMP(double t, const struct icmp* icmpp, int len,
					 int caplen, const u_char*& data)
	{
	EventHandlerPtr f = type == ICMP_ECHO ? icmp_echo_request : icmp_echo_reply;
	if ( ! f )
		return;

	int iid = ntohs(icmpp->icmp_hun.ih_idseq.icd_id);
	int iseq = ntohs(icmpp->icmp_hun.ih_idseq.icd_seq);

	BroString* payload = new BroString(data, caplen, 0);

	val_list* vl = new val_list;
	vl->append(BuildConnVal());
	vl->append(BuildICMPVal());
	vl->append(new Val(iid, TYPE_COUNT));
	vl->append(new Val(iseq, TYPE_COUNT));
	vl->append(new StringVal(payload));

	ConnectionEvent(f, vl);
	}


void ICMP_Context_Analyzer::NextICMP(double t, const struct icmp* icmpp,
				int len, int caplen, const u_char*& data)
	{
	EventHandlerPtr f = 0;
	switch ( type ) {
	case ICMP_UNREACH: f = icmp_unreachable; break;
	case ICMP_TIMXCEED: f = icmp_time_exceeded; break;
	}

	if ( f )
		{
		val_list* vl = new val_list;
		vl->append(BuildConnVal());
		vl->append(BuildICMPVal());
		vl->append(new Val(code, TYPE_COUNT));
		vl->append(ExtractICMPContext(caplen, data));

		ConnectionEvent(f, vl);
		}
	}


int ICMP_counterpart(int icmp_type, int icmp_code, bool& is_one_way)
	{
	is_one_way = false;

	// return the counterpart type if one exists.  This allows us
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
