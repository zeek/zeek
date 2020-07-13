// See the file "COPYING" in the main distribution directory for copyright.

#include "Null.h"
#include "NetVar.h"

using namespace zeek::packet_analysis::Null;

NullAnalyzer::NullAnalyzer()
	: zeek::packet_analysis::Analyzer("Null")
	{
	}

std::tuple<zeek::packet_analysis::AnalyzerResult, zeek::packet_analysis::identifier_t> NullAnalyzer::Analyze(Packet* packet)
	{
	auto& pdata = packet->cur_pos;

	if ( pdata + 4 >= packet->GetEndOfData() )
		{
		packet->Weird("null_analyzer_failed");
		return { AnalyzerResult::Failed, 0 };
		}

	identifier_t protocol = (pdata[3] << 24) + (pdata[2] << 16) + (pdata[1] << 8) + pdata[0];
	pdata += 4; // skip link header

	return { AnalyzerResult::Continue, protocol };
	}
