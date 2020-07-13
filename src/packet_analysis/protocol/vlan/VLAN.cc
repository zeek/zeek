// See the file "COPYING" in the main distribution directory for copyright.

#include "VLAN.h"
#include "NetVar.h"

using namespace zeek::packet_analysis::VLAN;

VLANAnalyzer::VLANAnalyzer()
	: zeek::packet_analysis::Analyzer("VLAN")
	{
	}

std::tuple<zeek::packet_analysis::AnalyzerResult, zeek::packet_analysis::identifier_t> VLANAnalyzer::Analyze(Packet* packet)
	{
	auto& pdata = packet->cur_pos;

	if ( pdata + 4 >= packet->GetEndOfData() )
		{
		packet->Weird("truncated_VLAN_header");
		return { AnalyzerResult::Failed, 0 };
		}

	auto& vlan_ref = packet->vlan != 0 ? packet->inner_vlan : packet->vlan;
	vlan_ref = ((pdata[0] << 8u) + pdata[1]) & 0xfff;

	identifier_t protocol = ((pdata[2] << 8u) + pdata[3]);
	packet->eth_type = protocol;
	pdata += 4; // Skip the VLAN header

	return { AnalyzerResult::Continue, protocol };
	}
