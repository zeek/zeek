// See the file "COPYING" in the main distribution directory for copyright.

#include "IPv4.h"

using namespace zeek::llanalyzer::IPv4;

IPv4Analyzer::IPv4Analyzer()
	: zeek::llanalyzer::Analyzer("IPv4")
	{
	}

std::tuple<zeek::llanalyzer::AnalyzerResult, zeek::llanalyzer::identifier_t> IPv4Analyzer::Analyze(Packet* packet)
	{
	packet->l3_proto = L3_IPV4;

	// Leave LL analyzer land
	return { AnalyzerResult::Terminate, 0 };
	}
