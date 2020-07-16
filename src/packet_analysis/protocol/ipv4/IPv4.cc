// See the file "COPYING" in the main distribution directory for copyright.

#include "IPv4.h"

using namespace zeek::packet_analysis::IPv4;

IPv4Analyzer::IPv4Analyzer()
	: zeek::packet_analysis::Analyzer("IPv4")
	{
	}

zeek::packet_analysis::AnalysisResultTuple IPv4Analyzer::Analyze(Packet* packet)
	{
	packet->l3_proto = L3_IPV4;

	// Leave packet analyzer land
	return { AnalyzerResult::Terminate, 0 };
	}
