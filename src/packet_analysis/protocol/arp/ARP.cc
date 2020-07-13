// See the file "COPYING" in the main distribution directory for copyright.

#include "ARP.h"

using namespace zeek::packet_analysis::ARP;

ARPAnalyzer::ARPAnalyzer()
	: zeek::packet_analysis::Analyzer("ARP")
	{
	}

std::tuple<zeek::packet_analysis::AnalyzerResult, zeek::packet_analysis::identifier_t> ARPAnalyzer::Analyze(Packet* packet)
	{
	// TODO: Make ARP analyzer a native LL analyzer
	packet->l3_proto = L3_ARP;

	// Leave LL analyzer land
	return { AnalyzerResult::Terminate, 0 };
	}
