// See the file "COPYING" in the main distribution directory for copyright.

#include "ARP.h"

using namespace zeek::packet_analysis::ARP;

ARPAnalyzer::ARPAnalyzer()
	: zeek::packet_analysis::Analyzer("ARP")
	{
	}

zeek::packet_analysis::AnalysisResultTuple ARPAnalyzer::Analyze(Packet* packet, const uint8_t*& data)
	{
	// TODO: Make ARP analyzer a native packet analyzer
	packet->l3_proto = L3_ARP;

	// Leave packet analyzer land
	return { AnalyzerResult::Terminate, 0 };
	}
