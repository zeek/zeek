// See the file "COPYING" in the main distribution directory for copyright.

#include "IPv6.h"

using namespace zeek::packet_analysis::IPv6;

IPv6Analyzer::IPv6Analyzer()
	: zeek::packet_analysis::Analyzer("IPv6")
	{
	}

std::tuple<zeek::packet_analysis::AnalyzerResult, zeek::packet_analysis::identifier_t> IPv6Analyzer::Analyze(Packet* packet)
	{
	packet->l3_proto = L3_IPV6;

	// Leave LL analyzer land
	return { AnalyzerResult::Terminate, 0 };
	}
