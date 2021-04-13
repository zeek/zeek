// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/packet_analysis/protocol/udp/UDP.h"
#include "zeek/RunState.h"

using namespace zeek::packet_analysis::UDP;
using namespace zeek::packet_analysis::IP;

UDPAnalyzer::UDPAnalyzer() : IPBasedAnalyzer("UDP", TRANSPORT_UDP, UDP_PORT_MASK, false)
	{
	}

UDPAnalyzer::~UDPAnalyzer()
	{
	}

bool UDPAnalyzer::AnalyzePacket(size_t len, const uint8_t* data, Packet* packet)
	{
	uint32_t min_hdr_len = sizeof(struct udphdr);
	if ( ! CheckHeaderTrunc(min_hdr_len, len, packet) )
		return false;

	ConnTuple id;
	id.src_addr = packet->ip_hdr->SrcAddr();
	id.dst_addr = packet->ip_hdr->DstAddr();
	const struct udphdr* up = (const struct udphdr *) packet->ip_hdr->Payload();
	id.src_port = up->uh_sport;
	id.dst_port = up->uh_dport;
	id.is_one_way = false;
	id.proto = TRANSPORT_UDP;

	ProcessConnection(id, packet, len);

	return true;
	}
void UDPAnalyzer::CreateTransportAnalyzer(Connection* conn, IPBasedTransportAnalyzer*& root,
                                          analyzer::pia::PIA*& pia, bool& check_port)
	{
	}

bool UDPAnalyzer::WantConnection(uint16_t src_port, uint16_t dst_port,
                                 const u_char* data, bool& flip_roles) const
	{
	flip_roles = IsLikelyServerPort(src_port) && ! IsLikelyServerPort(dst_port);
	return true;
	}
