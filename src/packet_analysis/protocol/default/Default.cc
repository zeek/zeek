// See the file "COPYING" in the main distribution directory for copyright.

#include "Default.h"
#include "NetVar.h"

using namespace zeek::packet_analysis::Default;

DefaultAnalyzer::DefaultAnalyzer()
	: zeek::packet_analysis::Analyzer("DefaultAnalyzer")
	{
	}

zeek::packet_analysis::AnalysisResultTuple DefaultAnalyzer::Analyze(Packet* packet)
	{
	auto& pdata = packet->cur_pos;

	// Assume we're pointing at IP. Just figure out which version.
	if ( pdata + sizeof(struct ip) >= packet->GetEndOfData() )
		{
		packet->Weird("packet_analyzer_truncated_header");
		return { AnalyzerResult::Failed, 0 };
		}

	auto ip = (const struct ip *)pdata;
	uint32_t protocol = ip->ip_v;

	return { AnalyzerResult::Continue, protocol };
	}
