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

zeek::packet_analysis::AnalyzerResult DefaultAnalyzer::AnalyzeInnerPacket(Packet* packet,
		const uint8_t*& data, uint32_t identifier) const
	{
	auto inner_analyzer = Lookup(identifier);

	if ( inner_analyzer == nullptr )
		{
		DBG_LOG(DBG_PACKET_ANALYSIS, "Default analysis in %s failed, could not find analyzer for identifier %#x.",
				GetAnalyzerName(), identifier);
		packet->Weird("no_suitable_analyzer_found");
		return AnalyzerResult::Failed;
		}

	DBG_LOG(DBG_PACKET_ANALYSIS, "Default analysis in %s succeeded, next layer identifier is %#x.",
			GetAnalyzerName(), identifier);
	return inner_analyzer->Analyze(packet, data);
	}