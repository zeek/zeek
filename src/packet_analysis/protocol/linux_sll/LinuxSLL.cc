// See the file "COPYING" in the main distribution directory for copyright.

#include "LinuxSLL.h"

using namespace zeek::packet_analysis::LinuxSLL;

LinuxSLLAnalyzer::LinuxSLLAnalyzer()
	: zeek::packet_analysis::Analyzer("LinuxSLL")
	{
	}

zeek::packet_analysis::AnalyzerResult LinuxSLLAnalyzer::Analyze(Packet* packet, const uint8_t*& data)
	{
	if ( data + sizeof(SLLHeader) >= packet->GetEndOfData() )
		{
		packet->Weird("truncated_Linux_SLL_header");
		return AnalyzerResult::Failed;
		}

	//TODO: Handle different ARPHRD_types
	auto hdr = (const SLLHeader*)data;

	uint32_t protocol = ntohs(hdr->protocol_type);
	packet->l2_src = (u_char*) &(hdr->addr);

	// SLL doesn't include a destination address in the header, but not setting l2_dst to something
	// here will cause crashes elsewhere.
	packet->l2_dst = Packet::L2_EMPTY_ADDR;

	data += sizeof(SLLHeader);
	return AnalyzeInnerPacket(packet, data, protocol);
	}
