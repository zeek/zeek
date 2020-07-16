// See the file "COPYING" in the main distribution directory for copyright.

#include "PPPSerial.h"
#include "NetVar.h"

using namespace zeek::packet_analysis::PPPSerial;

PPPSerialAnalyzer::PPPSerialAnalyzer()
	: zeek::packet_analysis::Analyzer("PPPSerial")
	{
	}

zeek::packet_analysis::AnalysisResultTuple PPPSerialAnalyzer::Analyze(Packet* packet)
	{
	auto& pdata = packet->cur_pos;

	// Extract protocol identifier
	uint32_t protocol = (pdata[2] << 8) + pdata[3];
	pdata += 4; // skip link header

	return { AnalyzerResult::Continue, protocol };
	}
