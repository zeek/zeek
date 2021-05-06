// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/packet_analysis/protocol/tcp/TCP.h"
#include "zeek/RunState.h"

using namespace zeek::packet_analysis::TCP;
using namespace zeek::packet_analysis::IP;

TCPAnalyzer::TCPAnalyzer() : IPBasedAnalyzer("TCP", TRANSPORT_TCP, TCP_PORT_MASK, false)
	{
	}

TCPAnalyzer::~TCPAnalyzer()
	{
	}

bool TCPAnalyzer::BuildConnTuple(size_t len, const uint8_t* data, Packet* packet,
                                 ConnTuple& tuple)
	{
	uint32_t min_hdr_len = sizeof(struct tcphdr);
	if ( ! CheckHeaderTrunc(min_hdr_len, len, packet) )
		return false;

	tuple.src_addr = packet->ip_hdr->SrcAddr();
	tuple.dst_addr = packet->ip_hdr->DstAddr();

	data = packet->ip_hdr->Payload();

	const struct tcphdr* tp = (const struct tcphdr *) data;
	tuple.src_port = tp->th_sport;
	tuple.dst_port = tp->th_dport;
	tuple.is_one_way = false;
	tuple.proto = TRANSPORT_TCP;

	return true;
	}

bool TCPAnalyzer::WantConnection(uint16_t src_port, uint16_t dst_port,
                                 const u_char* data, bool& flip_roles) const
	{
	flip_roles = false;
	const struct tcphdr* tp = (const struct tcphdr*) data;
	uint8_t tcp_flags = tp->th_flags;

	if ( ! (tcp_flags & TH_SYN) || (tcp_flags & TH_ACK) )
		{
		// The new connection is starting either without a SYN,
		// or with a SYN ack. This means it's a partial connection.
		if ( ! zeek::detail::partial_connection_ok )
			return false;

		if ( tcp_flags & TH_SYN && ! zeek::detail::tcp_SYN_ack_ok )
			return false;

		// Try to guess true responder by the port numbers.
		// (We might also think that for SYN acks we could
		// safely flip the roles, but that doesn't work
		// for stealth scans.)
		if ( IsLikelyServerPort(src_port) )
			{ // connection is a candidate for flipping
			if ( IsLikelyServerPort(dst_port) )
				// Hmmm, both source and destination
				// are plausible.  Heuristic: flip only
				// if (1) this isn't a SYN ACK (to avoid
				// confusing stealth scans) and
				// (2) dest port > src port (to favor
				// more plausible servers).
				flip_roles = ! (tcp_flags & TH_SYN) && src_port < dst_port;
			else
				// Source is plausible, destination isn't.
				flip_roles = true;
			}
		}

	return true;
	}

void TCPAnalyzer::CreateTransportAnalyzer(Connection* conn, IPBasedTransportAnalyzer*& root,
                                          analyzer::pia::PIA*& pia, bool& check_port)
	{
	}
