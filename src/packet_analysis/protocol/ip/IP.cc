// See the file "COPYING" in the main distribution directory for copyright.

#include "IP.h"
#include "NetVar.h"

using namespace zeek::packet_analysis::IP;

IPAnalyzer::IPAnalyzer()
	: zeek::packet_analysis::Analyzer("IP")
	{
	}

zeek::packet_analysis::AnalyzerResult IPAnalyzer::Analyze(Packet* packet, const uint8_t*& data)
	{
	// Assume we're pointing at IP. Just figure out which version.
	if ( data + sizeof(struct ip) >= packet->GetEndOfData() )
		{
		packet->Weird("packet_analyzer_truncated_header");
		return AnalyzerResult::Failed;
		}

	auto ip = (const struct ip *)data;
	uint32_t protocol = ip->ip_v;

	auto inner_analyzer = Lookup(protocol);

	if ( inner_analyzer == nullptr )
		{
		DBG_LOG(DBG_PACKET_ANALYSIS, "Analysis in %s failed, could not find analyzer for identifier %#x.",
				GetAnalyzerName(), protocol);
		packet->Weird("no_suitable_analyzer_found");
		return AnalyzerResult::Failed;
		}

	DBG_LOG(DBG_PACKET_ANALYSIS, "Analysis in %s succeeded, next layer identifier is %#x.",
			GetAnalyzerName(), protocol);
	return inner_analyzer->Analyze(packet, data);
	}