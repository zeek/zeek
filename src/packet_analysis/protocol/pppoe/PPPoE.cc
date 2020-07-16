// See the file "COPYING" in the main distribution directory for copyright.

#include "PPPoE.h"
#include "NetVar.h"

using namespace zeek::packet_analysis::PPPoE;

PPPoEAnalyzer::PPPoEAnalyzer()
	: zeek::packet_analysis::Analyzer("PPPoE")
	{
	}

zeek::packet_analysis::AnalysisResultTuple PPPoEAnalyzer::Analyze(Packet* packet)
	{
	auto& pdata = packet->cur_pos;

	if ( pdata + 8 >= packet->GetEndOfData() )
		{
		packet->Weird("truncated_pppoe_header");
		return { AnalyzerResult::Failed, 0 };
		}

	// Extract protocol identifier
	uint32_t protocol = (pdata[6] << 8u) + pdata[7];
	pdata += 8; // Skip the PPPoE session and PPP header

	return { AnalyzerResult::Continue, protocol };
	}
