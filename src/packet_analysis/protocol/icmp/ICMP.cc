// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/packet_analysis/protocol/icmp/ICMP.h"

#include <netinet/icmp6.h>

#include "zeek/RunState.h"
#include "zeek/session/Manager.h"

using namespace zeek::packet_analysis::ICMP;
using namespace zeek::packet_analysis::IP;

ICMPAnalyzer::ICMPAnalyzer() : IPBasedAnalyzer("ICMP", TRANSPORT_ICMP, ICMP_PORT_MASK, false)
	{
	}

ICMPAnalyzer::~ICMPAnalyzer()
	{
	}

bool ICMPAnalyzer::AnalyzePacket(size_t len, const uint8_t* data, Packet* packet)
	{
	if ( ! CheckHeaderTrunc(ICMP_MINLEN, len, packet) )
		return false;

	ConnTuple id;
	id.src_addr = packet->ip_hdr->SrcAddr();
	id.dst_addr = packet->ip_hdr->DstAddr();
	id.proto = TRANSPORT_ICMP;

	const struct icmp* icmpp = (const struct icmp *) data;
	id.src_port = htons(icmpp->icmp_type);

	if ( packet->proto == IPPROTO_ICMP )
		id.dst_port = htons(ICMP4_counterpart(icmpp->icmp_type, icmpp->icmp_code, id.is_one_way));
	else if ( packet->proto == IPPROTO_ICMPV6 )
		id.dst_port = htons(ICMP6_counterpart(icmpp->icmp_type, icmpp->icmp_code, id.is_one_way));
	else
		reporter->InternalError("Reached ICMP packet analyzer with unknown packet protocol %x",
		                        packet->proto);

	ProcessConnection(id, packet, len);

	return true;
	}

void ICMPAnalyzer::ContinueProcessing(Connection* c, double t, bool is_orig, int remaining, Packet* pkt)
	{
	}

void ICMPAnalyzer::CreateTransportAnalyzer(Connection* conn, IPBasedTransportAnalyzer*& root,
                                           analyzer::pia::PIA*& pia, bool& check_port)
	{
	}


int ICMPAnalyzer::ICMP4_counterpart(int icmp_type, int icmp_code, bool& is_one_way)
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
	case ICMP_ROUTERADVERT:	return ICMP_ROUTERSOLICIT;

	case ICMP_MASKREQ:		return ICMP_MASKREPLY;
	case ICMP_MASKREPLY:		return ICMP_MASKREQ;

	default:			is_one_way = true; return icmp_code;
	}
	}

int ICMPAnalyzer::ICMP6_counterpart(int icmp_type, int icmp_code, bool& is_one_way)
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
