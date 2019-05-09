// See the file "COPYING" in the main distribution directory for copyright.

#include "PPPSerial.h"
#include "NetVar.h"

using namespace zeek::llanalyzer::PPPSerial;

PPPSerialAnalyzer::PPPSerialAnalyzer()
	: zeek::llanalyzer::Analyzer("PPPSerial")
	{
	}

std::tuple<zeek::llanalyzer::AnalyzerResult, zeek::llanalyzer::identifier_t> PPPSerialAnalyzer::Analyze(Packet* packet)
	{
	auto& pdata = packet->cur_pos;

	// Extract protocol identifier
	identifier_t protocol = (pdata[2] << 8) + pdata[3];
	pdata += 4; // skip link header

	return { AnalyzerResult::Continue, protocol };
	}
