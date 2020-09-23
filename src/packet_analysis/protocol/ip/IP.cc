// See the file "COPYING" in the main distribution directory for copyright.

#include "IP.h"
#include "NetVar.h"

using namespace zeek::packet_analysis::IP;

IPAnalyzer::IPAnalyzer()
	: zeek::packet_analysis::Analyzer("IP")
	{
	}

bool IPAnalyzer::AnalyzePacket(size_t len, const uint8_t* data, Packet* packet)
	{
	// Assume we're pointing at IP. Just figure out which version.
	if ( sizeof(struct ip) >= len )
		{
		packet->Weird("packet_analyzer_truncated_header");
		return false;
		}

	auto ip = (const struct ip *)data;
	uint32_t protocol = ip->ip_v;

	auto inner_analyzer = Lookup(protocol);
	if ( inner_analyzer == nullptr )
		{
		DBG_LOG(DBG_PACKET_ANALYSIS, "Analysis in %s failed, could not find analyzer for identifier %#x.",
				GetAnalyzerName(), protocol);
		packet->Weird("no_suitable_analyzer_found");
		return false;
		}

	DBG_LOG(DBG_PACKET_ANALYSIS, "Analysis in %s succeeded, next layer identifier is %#x.",
			GetAnalyzerName(), protocol);
	return inner_analyzer->AnalyzePacket(len, data, packet);
	}