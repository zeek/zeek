// See the file "COPYING" in the main distribution directory for copyright.

#include "IPv6.h"

using namespace zeek::packet_analysis::IPv6;

IPv6Analyzer::IPv6Analyzer()
	: zeek::packet_analysis::Analyzer("IPv6")
	{
	}

zeek::packet_analysis::AnalysisResultTuple IPv6Analyzer::Analyze(Packet* packet, const uint8_t*& data)
	{
	packet->l3_proto = L3_IPV6;

	// Leave packet analyzer land
	return { AnalyzerResult::Terminate, 0 };
	}
