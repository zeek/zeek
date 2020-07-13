// See the file "COPYING" in the main distribution directory for copyright.

#include "PPPSerial.h"
#include "NetVar.h"

using namespace zeek::packet_analysis::PPPSerial;

PPPSerialAnalyzer::PPPSerialAnalyzer()
	: zeek::packet_analysis::Analyzer("PPPSerial")
	{
	}

std::tuple<zeek::packet_analysis::AnalyzerResult, zeek::packet_analysis::identifier_t> PPPSerialAnalyzer::Analyze(Packet* packet)
	{
	auto& pdata = packet->cur_pos;

	// Extract protocol identifier
	identifier_t protocol = (pdata[2] << 8) + pdata[3];
	pdata += 4; // skip link header

	return { AnalyzerResult::Continue, protocol };
	}
