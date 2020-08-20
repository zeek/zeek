// See the file "COPYING" in the main distribution directory for copyright.

#include "Default.h"
#include "NetVar.h"

using namespace zeek::packet_analysis::Default;

DefaultAnalyzer::DefaultAnalyzer()
	: zeek::packet_analysis::Analyzer("DefaultAnalyzer")
	{
	}

zeek::packet_analysis::AnalyzerResult DefaultAnalyzer::Analyze(Packet* packet, const uint8_t*& data)
	{
	// Assume we're pointing at IP. Just figure out which version.
	if ( data + sizeof(struct ip) >= packet->GetEndOfData() )
		{
		packet->Weird("packet_analyzer_truncated_header");
		return AnalyzerResult::Failed;
		}

	auto ip = (const struct ip *)data;
	uint32_t protocol = ip->ip_v;

	return AnalyzeInnerPacket(packet, data, protocol);
	}
