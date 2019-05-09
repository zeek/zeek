// See the file "COPYING" in the main distribution directory for copyright.

#include "ARP.h"

using namespace zeek::llanalyzer::ARP;

ARPAnalyzer::ARPAnalyzer()
	: zeek::llanalyzer::Analyzer("ARP")
	{
	}

std::tuple<zeek::llanalyzer::AnalyzerResult, zeek::llanalyzer::identifier_t> ARPAnalyzer::Analyze(Packet* packet)
	{
	// TODO: Make ARP analyzer a native LL analyzer
	packet->l3_proto = L3_ARP;

	// Leave LL analyzer land
	return { AnalyzerResult::Terminate, 0 };
	}
