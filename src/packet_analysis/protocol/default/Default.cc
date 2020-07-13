// See the file "COPYING" in the main distribution directory for copyright.

#include "Default.h"
#include "NetVar.h"

using namespace zeek::packet_analysis::Default;

DefaultAnalyzer::DefaultAnalyzer()
	: zeek::packet_analysis::Analyzer("DefaultAnalyzer")
	{
	}

std::tuple<zeek::packet_analysis::AnalyzerResult, zeek::packet_analysis::identifier_t> DefaultAnalyzer::Analyze(Packet* packet)
	{
	auto& pdata = packet->cur_pos;

	// Assume we're pointing at IP. Just figure out which version.
	if ( pdata + sizeof(struct ip) >= packet->GetEndOfData() )
		{
		packet->Weird("default_ll_analyser_failed");
		return { AnalyzerResult::Failed, 0 };
		}

	auto ip = (const struct ip *)pdata;
	identifier_t protocol = ip->ip_v;

	return { AnalyzerResult::Continue, protocol };
	}
