// $Id: ICMP.cc 6219 2008-10-01 05:39:07Z vern $
//
// See the file "COPYING" in the main distribution directory for copyright.

#include "config.h"

#include "Net.h"
#include "NetVar.h"
#include "Event.h"
#include "ICMP.h"

#include <netinet/icmp6.h>



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


	//We need a separate calculation for ICMP6 checksums, pseudoheader is appended to the
	//ICMP6 checksum calculation, which is different from ICMP4
#ifdef BROv6


	if (ip->NextProto() == IPPROTO_ICMPV6  && ! ignore_checksums &&
			caplen >= len && icmp6_checksum(icmpp,ip->IP6_Hdr(),len )!= 0xffff )
		{
		Weird("bad_ICMP6_checksum");
		return;
		}
	else if (ip->NextProto() != IPPROTO_ICMPV6 && ! ignore_checksums &&
			caplen >= len && icmp_checksum(icmpp, len) != 0xffff )
		{
		Weird("bad_ICMP_checksum");
		return;
		}



#else

	if ( ! ignore_checksums && caplen >= len &&
		     icmp_checksum(icmpp, len) != 0xffff )
		{
		Weird("bad_ICMP_checksum");
		return;
		}
#endif



	Conn()->SetLastTime(current_timestamp);

	if ( rule_matcher )
		{
		if ( ! matcher_state.MatcherInitialized(is_orig) )
			matcher_state.InitEndpointMatcher(this, ip, len, is_orig, 0);
		}

	type = icmpp->icmp_type;
	code = icmpp->icmp_code;

	// Move past common portion of ICMP header. //OK for ICMPv6?
	data += 8;
	caplen -= 8;
	len -= 8;

	int& len_stat = is_orig ? request_len : reply_len;
	if ( len_stat < 0 )
		len_stat = len;
	else
		len_stat += len;

	NextICMP(current_timestamp, icmpp, len, caplen, data, ip);

	if ( rule_matcher )
		matcher_state.Match(Rule::PAYLOAD, data, len, is_orig,
					false, false, true);
	}



/********************Generic analyzer for all ICMP4/ICMP6******************************/
void ICMP_Analyzer::NextICMP(double  t , const struct icmp*  icmpp , int len , int caplen,
		const u_char*& data, const IP_Hdr* ip_hdr )
    {
	int ICMP6Flag = 0;

	//printf("Executing: ICMP_Analyzer::NextICMP\n");
	//printf("New analyzer structure\n");

	if ( ip_hdr->NextProto() == IPPROTO_ICMPV6 )
		{
		//printf("ICMP6!\n");
		ICMP6Flag = 1;

			switch (type) //Add new ICMP6 functions here, you can also use codes to narrow the area of single functions.
			{
			//All the echo stuff here
			case ICMP6_ECHO_REQUEST:
			case ICMP6_ECHO_REPLY:
			Echo(t, icmpp, len, caplen, data, ip_hdr);
			break;


			//Error messages all have the same structure for their context, and are handled by the same function.
			case ICMP6_PARAM_PROB:
			case ICMP6_TIME_EXCEEDED:
			case ICMP6_PACKET_TOO_BIG:
			case ICMP6_DST_UNREACH:
			Context(t, icmpp, len, caplen, data, ip_hdr);
			break;

			//All router related stuff should eventually be handled by the Router()
			case ND_REDIRECT:
			case ND_ROUTER_SOLICIT:
			case ICMP6_ROUTER_RENUMBERING:
			case ND_ROUTER_ADVERT:
			Router(t, icmpp, len, caplen, data, ip_hdr); //currently only logs the router stuff for other than router_advert
			break;

			/* listed for convenience
			case ICMP6_PARAM_PROB:			  		break;
			case MLD_LISTENER_QUERY: 				break;
			case MLD_LISTENER_REPORT:				break;
			case MLD_LISTENER_REDUCTION:			break;
			case ND_NEIGHBOR_SOLICIT:				break;
			case ND_NEIGHBOR_ADVERT:				break;
			case ND_REDIRECT:						break;
			case ICMP6_ROUTER_RENUMBERING: 			break;
			case ND_NEIGHBOR_SOLICIT:		 		break;
			case ND_NEIGHBOR_ADVERT:	 			break;
			case ICMP6_TIME_EXCEEDED:				break;
			*/

			default: ICMPEvent(icmp_sent, ICMP6Flag); break;
			}
		}
	else if ( ip_hdr->NextProto() == IPPROTO_ICMP )
		{

			switch (type) //Add new ICMP4 functions here
			{
			case ICMP_ECHO:
			case ICMP_ECHOREPLY:
			Echo(t, icmpp, len, caplen, data, ip_hdr);
			break;

			case ICMP_UNREACH:
			case ICMP_TIMXCEED:
			Context(t, icmpp, len, caplen, data, ip_hdr);
			break;

			default: ICMPEvent(icmp_sent, ICMP6Flag); break;
			}


		}
	else
		Weird("Malformed ip header");
    }


void ICMP_Analyzer::ICMPEvent(EventHandlerPtr f, int ICMP6Flag)
    {
	if ( ! f )
			return;


	val_list* vl = new val_list;
	vl->append(BuildConnVal());
	vl->append(BuildICMPVal(ICMP6Flag));
	//if ( f == icmp_sent ) //for now, testing purposes
	vl->append(new Val(ICMP6Flag, TYPE_BOOL));

	ConnectionEvent(f, vl);
	}


RecordVal* ICMP_Analyzer::BuildICMPVal(int ICMP6Flag)
	{
	if ( ! icmp_conn_val )
		{
		icmp_conn_val = new RecordVal(icmp_conn);

		icmp_conn_val->Assign(0, new AddrVal(Conn()->OrigAddr()));
		icmp_conn_val->Assign(1, new AddrVal(Conn()->RespAddr()));

		if ( ICMP6Flag == 1 )
			icmp_conn_val->Assign(2, new Val(Type6to4(type), TYPE_COUNT)); //to avoid errors in getting the message type *name* right on the scripting level, type number will be different from true ipv6
		else
			icmp_conn_val->Assign(2, new Val(type, TYPE_COUNT));


		icmp_conn_val->Assign(3, new Val(code, TYPE_COUNT));
		icmp_conn_val->Assign(4, new Val(len, TYPE_COUNT));
		}

	Ref(icmp_conn_val);

	return icmp_conn_val;
	}

RecordVal* ICMP_Analyzer::ExtractICMP4Context(int len, const u_char*& data)
	{
	/**
	 * For use only with ICMP4, ICMPV6 context extraction is still non-functional
	 */

	const IP_Hdr ip_hdr_data((const struct ip*) data);
	const IP_Hdr* ip_hdr = &ip_hdr_data;
	int ICMP6Flag = 0;

	uint32 ip_hdr_len = ip_hdr->HdrLen();

	uint32 ip_len, frag_offset;
	TransportProto proto = TRANSPORT_UNKNOWN;
	int DF, MF, bad_hdr_len, bad_checksum;
	uint32 src_addr, dst_addr,src_addr2, dst_addr2;
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
			ip_len = ip_hdr->TotalLen();
			bad_checksum = ones_complement_checksum((void*) ip_hdr->IP4_Hdr(), ip_hdr_len, 0) != 0xffff;

			src_addr = ip_hdr->SrcAddr4();
			dst_addr = ip_hdr->DstAddr4();

			switch ( ip_hdr->NextProto() ) {
			case 1:		proto = TRANSPORT_ICMP; break;
			case 6:		proto = TRANSPORT_TCP; break;
			case 17:	proto = TRANSPORT_UDP; break;

			// Default uses TRANSPORT_UNKNOWN, per initialization above.
			}

			uint32 frag_field = ip_hdr->FragField();
			DF = ip_hdr->DF();
			MF = frag_field & 0x2000;
			frag_offset = frag_field & /* IP_OFFMASK not portable */ 0x1fff;

			const u_char* transport_hdr = ((u_char *) ip_hdr->IP4_Hdr() + ip_hdr_len);

			if ( uint32(len) < ip_hdr_len + 4 ) //what is this value for ipv6?
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
				dst_port = ntohs(ICMP4_counterpart(icmpp->icmp_type,
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
		iprec->Assign(8, new Val(ICMP6Flag, TYPE_BOOL));

		return iprec;
		}




RecordVal* ICMP_Analyzer::ExtractICMP6Context(int len, const u_char*& data)
	{
	/**
	 * For use with ICMP6 error message context extraction (possibly very frail function)
	 */

	const IP_Hdr ip_hdr_data((const struct ip6_hdr*) data);
	const IP_Hdr* ip_hdr = &ip_hdr_data;
	int ICMP6Flag = 1;
	int DF = 0, MF = 0, bad_hdr_len = 0, bad_checksum = 0;

	uint32 ip_hdr_len = ip_hdr->HdrLen(); //should always be 40
	uint32* src_addr;
	uint32* dst_addr;
	uint32 ip_len, frag_offset = 0;
	TransportProto proto = TRANSPORT_UNKNOWN;
	uint32 src_port, dst_port;

	if ( ip_hdr_len < sizeof(struct ip6_hdr) || ip_hdr_len != 40 )
		{
		bad_hdr_len = 1;
		ip_len = 0;
		src_addr = dst_addr = 0;
		src_port = dst_port = 0;
		}
	else
		{
		ip_len = ip_hdr->TotalLen();

		src_addr = (uint32 *) ip_hdr->SrcAddr();
		dst_addr = (uint32 *) ip_hdr->DstAddr();



		switch ( ip_hdr->NextProto() ) {
		case 1:		proto = TRANSPORT_ICMP; break;
		case 6:		proto = TRANSPORT_TCP; break;
		case 17:	proto = TRANSPORT_UDP; break;
		case 58:	proto = TRANSPORT_ICMP; break;  //TransportProto Hack

		// Default uses TRANSPORT_UNKNOWN, per initialization above.
		}


		const u_char* transport_hdr = ((u_char *)ip_hdr->IP6_Hdr() + ip_hdr_len);

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
			dst_port = ntohs(ICMP6_counterpart(icmpp->icmp_type,
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

	//TransportProto Hack
	if ( ip_hdr->NextProto() == 58 || 17 ) //if the encap packet is ICMPv6 we force this... (cause there is no IGMP (by that name) for ICMPv6), rather ugly hack once more
		{
		iprec->Assign(2, new Val(58, TYPE_COUNT));
		}
	else
		{
		iprec->Assign(2, new Val(proto, TYPE_COUNT));
		}

	iprec->Assign(3, new Val(frag_offset, TYPE_COUNT)); //NA for ip6
	iprec->Assign(4, new Val(bad_hdr_len, TYPE_BOOL));
	iprec->Assign(5, new Val(bad_checksum, TYPE_BOOL));
	iprec->Assign(6, new Val(MF, TYPE_BOOL));  //NA for ip6
	iprec->Assign(7, new Val(DF, TYPE_BOOL));  //NA for ip6
	iprec->Assign(8, new Val(ICMP6Flag, TYPE_BOOL)); //ICMP6Flag

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


void ICMP_Analyzer::Echo(double t, const struct icmp* icmpp, int len,
					 int caplen, const u_char*& data, const IP_Hdr* ip_hdr)
	{ //For handling all Echo related ICMP messages
	EventHandlerPtr f = 0;
	int ICMP6Flag = 0;

	//printf("Executing: Echo, NextProto:%d\n",ip_hdr->NextProto());

	if ( ip_hdr->NextProto() == IPPROTO_ICMPV6 )
		{
		f = type == ICMP6_ECHO_REQUEST ? icmp_echo_request : icmp_echo_reply;
		ICMP6Flag = 1;
		}
	else
		f = type == ICMP_ECHO ? icmp_echo_request : icmp_echo_reply;

	if ( ! f )
		return;

	int iid = ntohs(icmpp->icmp_hun.ih_idseq.icd_id);
	int iseq = ntohs(icmpp->icmp_hun.ih_idseq.icd_seq);

	//printf("Check these values: iid:[%d]  iseq:[%d]\n",iid,iseq);

	BroString* payload = new BroString(data, caplen, 0);

	val_list* vl = new val_list;
	vl->append(BuildConnVal());
	vl->append(BuildICMPVal(ICMP6Flag));
	vl->append(new Val(iid, TYPE_COUNT));
	vl->append(new Val(iseq, TYPE_COUNT));
	vl->append(new StringVal(payload));
	vl->append(new Val(ICMP6Flag, TYPE_BOOL));

	ConnectionEvent(f, vl);
	}










void ICMP_Analyzer::Router(double t, const struct icmp* icmpp, int len,
			 int caplen, const u_char*& data, const IP_Hdr* /*ip_hdr*/)
	//For handling router related ICMP messages,
	{
	EventHandlerPtr f = 0;
	int ICMP6Flag = 1;

	switch ( type )
		{
		case ND_ROUTER_ADVERT: 			f = icmp_router_advertisement;	break;

		case ND_REDIRECT:
		case ND_ROUTER_SOLICIT:
		case ICMP6_ROUTER_RENUMBERING:
		default: 						ICMPEvent(icmp_sent,ICMP6Flag);	return;
		}

	val_list* vl = new val_list;
	vl->append(BuildConnVal());
	vl->append(BuildICMPVal(ICMP6Flag));
	vl->append(new Val(ICMP6Flag, TYPE_BOOL));

	ConnectionEvent(f, vl);
	}














void ICMP_Analyzer::Context(double t, const struct icmp* icmpp,
				int len, int caplen, const u_char*& data, const IP_Hdr* ip_hdr)
	{//For handling the ICMP error messages

	EventHandlerPtr f = 0;
	int ICMP6Flag = 0;


	if ( ip_hdr->NextProto()  == IPPROTO_ICMPV6 ) //is ip6
	{

		ICMP6Flag = 1;
		//printf("Executing: Context for ICMPv6\n");

		switch ( type )
			{
			case ICMP6_DST_UNREACH: 		f = icmp_unreachable; 	break;
			case ICMP6_PARAM_PROB:			f = icmp_error_message; break;
			case ICMP6_TIME_EXCEEDED:		f = icmp_error_message; break;
			case ICMP6_PACKET_TOO_BIG:		f = icmp_error_message; break;
			}

		if ( f )
			{
			val_list* vl = new val_list;
			vl->append(BuildConnVal()); //check for ip6 functionality
			vl->append(BuildICMPVal(ICMP6Flag)); //check for ip6 functionality
			vl->append(new Val(code, TYPE_COUNT));
			vl->append(ExtractICMP6Context(caplen, data));

			ConnectionEvent(f, vl);
			}

	}
	else if ( ip_hdr->NextProto()  == IPPROTO_ICMP )
	{
		//printf("Executing: Context for ICMP\n");
		switch ( type )
			{
			case ICMP_UNREACH: f = icmp_unreachable; break;
			case ICMP_TIMXCEED: f = icmp_error_message; break;
			}

		if ( f )
			{
			val_list* vl = new val_list;
			vl->append(BuildConnVal());
			vl->append(BuildICMPVal(ICMP6Flag));
			vl->append(new Val(code, TYPE_COUNT));
			vl->append(ExtractICMP4Context(caplen, data));


			ConnectionEvent(f, vl);
			}

		}
	else
		{
		Weird("ICMP packet, invalid data\n"); //make this more descriptive
		}
	}



int ICMP4_counterpart(int icmp_type, int icmp_code, bool& is_one_way)
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

int ICMP6_counterpart(int icmp_type, int icmp_code, bool& is_one_way)
	{
	is_one_way = false;

	/**ICMP6 version of the ICMP4_counterpart, under work**/
	//not yet used anywhere, for the context class

	switch ( icmp_type ) {


	case ICMP6_ECHO_REQUEST:			return ICMP6_ECHO_REPLY;
	case ICMP6_ECHO_REPLY:				return ICMP6_ECHO_REQUEST;

	case ND_ROUTER_SOLICIT:				return ND_ROUTER_ADVERT;
	case ND_ROUTER_ADVERT:				return ND_ROUTER_SOLICIT;

	case ND_NEIGHBOR_SOLICIT:			return ND_NEIGHBOR_ADVERT;
	case ND_NEIGHBOR_ADVERT:			return ND_NEIGHBOR_SOLICIT;

	case MLD_LISTENER_QUERY: 			return MLD_LISTENER_REPORT;
	case MLD_LISTENER_REPORT:			return MLD_LISTENER_QUERY;

	case 139:							return 140; //ICMP node information query and response respectively (not defined in icmp6.h)
	case 140:							return 139;

	case 144:							return 145; //Home Agent Address Discovery Request Message and reply
	case 145:							return 144;

	//check the rest of the counterparts

	default:			is_one_way = true; return icmp_code;
	}
	}

	//For mapping ICMP types and codes of v6 to v4. Because we are using same events for both icmpv4 and icmpv6 there is some overlap
	//in ICMP types. If this function is used, the name (checked from a table in the scripts) will be incorrect for the listed
	//types, but the names will be correct for all ICMP types.
	int Type6to4(int icmp_type)
	{
		switch ( icmp_type ) //For these three values, the type number will be wrong if this is used!
		{ //easy way to disable this is just to comment all the cases out, and leave only the default.
		case ICMP6_DST_UNREACH:		return ICMP_UNREACH; 	break;
		case ICMP6_TIME_EXCEEDED:	return ICMP_TIMXCEED;	break;
		case ICMP6_PARAM_PROB:		return ICMP_PARAMPROB;	break;

		default: 					return icmp_type;		break;
		}
	}

	int Code6to4(int icmp_code) //not used yet for anything
	{
		switch ( icmp_code )
		{
		default: 					return icmp_code; 		break;
		}
	}


