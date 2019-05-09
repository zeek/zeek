// See the file "COPYING" in the main distribution directory for copyright.

#include "LinuxSLL.h"

using namespace zeek::llanalyzer::LinuxSLL;

LinuxSLLAnalyzer::LinuxSLLAnalyzer()
	: zeek::llanalyzer::Analyzer("LinuxSLL")
	{
	}

std::tuple<zeek::llanalyzer::AnalyzerResult, zeek::llanalyzer::identifier_t> LinuxSLLAnalyzer::Analyze(Packet* packet)
	{
	auto& pdata = packet->cur_pos;

	if ( pdata + sizeof(SLLHeader) >= packet->GetEndOfData() )
		{
		packet->Weird("truncated_Linux_SLL_header");
		return { AnalyzerResult::Failed, 0 };
		}

	//TODO: Handle different ARPHRD_types
	auto hdr = (const SLLHeader*)pdata;

	identifier_t protocol = ntohs(hdr->protocol_type);
	packet->l2_src = (u_char*) &(hdr->addr);

	// SLL doesn't include a destination address in the header, but not setting l2_dst to something
	// here will cause crashes elsewhere.
	packet->l2_dst = Packet::L2_EMPTY_ADDR;

	pdata += sizeof(SLLHeader);
	return { AnalyzerResult::Continue, protocol };
	}
