// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/packet_analysis/protocol/linux_sll/LinuxSLL.h"

using namespace zeek::packet_analysis::LinuxSLL;

LinuxSLLAnalyzer::LinuxSLLAnalyzer()
	: zeek::packet_analysis::Analyzer("LinuxSLL")
	{
	}

bool LinuxSLLAnalyzer::AnalyzePacket(size_t len, const uint8_t* data, Packet* packet)
	{
	auto len_sll_hdr = sizeof(SLLHeader);
	if ( len_sll_hdr >= len )
		{
		Weird("truncated_Linux_SLL_header", packet);
		return false;
		}

	// Note: We assume to see an Ethertype and don't consider different ARPHRD_types
	// (see https://www.tcpdump.org/linktypes/LINKTYPE_LINUX_SLL.html)
	auto hdr = (const SLLHeader*)data;

	uint32_t protocol = ntohs(hdr->protocol_type);
	packet->l2_src = (u_char*) &(hdr->addr);

	// SLL doesn't include a destination address in the header, but not setting l2_dst to something
	// here will cause crashes elsewhere.
	packet->l2_dst = Packet::L2_EMPTY_ADDR;

	return ForwardPacket(len - len_sll_hdr, data + len_sll_hdr, packet, protocol);
	}
