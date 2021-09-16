// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/packet_analysis/protocol/root/Root.h"

using namespace zeek::packet_analysis::Root;

RootAnalyzer::RootAnalyzer() : zeek::packet_analysis::Analyzer("Root") { }

bool RootAnalyzer::AnalyzePacket(size_t len, const uint8_t* data, Packet* packet)
	{
	reporter->InternalError("AnalyzePacket() was called for the root analyzer.");
	}
