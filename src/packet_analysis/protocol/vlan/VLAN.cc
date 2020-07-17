// See the file "COPYING" in the main distribution directory for copyright.

#include "VLAN.h"
#include "NetVar.h"

using namespace zeek::packet_analysis::VLAN;

VLANAnalyzer::VLANAnalyzer()
	: zeek::packet_analysis::Analyzer("VLAN")
	{
	}

zeek::packet_analysis::AnalysisResultTuple VLANAnalyzer::Analyze(Packet* packet, const uint8_t*& data)
	{
	if ( data + 4 >= packet->GetEndOfData() )
		{
		packet->Weird("truncated_VLAN_header");
		return { AnalyzerResult::Failed, 0 };
		}

	auto& vlan_ref = packet->vlan != 0 ? packet->inner_vlan : packet->vlan;
	vlan_ref = ((data[0] << 8u) + data[1]) & 0xfff;

	uint32_t protocol = ((data[2] << 8u) + data[3]);
	packet->eth_type = protocol;
	data += 4; // Skip the VLAN header

	return { AnalyzerResult::Continue, protocol };
	}
