// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/packet_analysis/protocol/linux_sll2/LinuxSLL2.h"

using namespace zeek::packet_analysis::LinuxSLL2;

LinuxSLL2Analyzer::LinuxSLL2Analyzer() : zeek::packet_analysis::Analyzer("LinuxSLL2") { }

bool LinuxSLL2Analyzer::AnalyzePacket(size_t len, const uint8_t* data, Packet* packet)
	{
	auto len_sll2_hdr = sizeof(SLL2Header);
	if ( len_sll2_hdr >= len )
		{
		Weird("truncated_Linux_SLL2_header", packet);
		return false;
		}

	// Note: We assume to see an Ethertype and don't consider different ARPHRD_types
	// (see https://www.tcpdump.org/linktypes/LINKTYPE_LINUX_SLL2.html)
	auto hdr = (const SLL2Header*)data;

	uint32_t protocol = ntohs(hdr->protocol_type);
	packet->l2_src = (u_char*)&(hdr->addr);

	// SLL doesn't include a destination address in the header, but not setting l2_dst to something
	// here will cause crashes elsewhere.
	packet->l2_dst = Packet::L2_EMPTY_ADDR;

	return ForwardPacket(len - len_sll2_hdr, data + len_sll2_hdr, packet, protocol);
	}
