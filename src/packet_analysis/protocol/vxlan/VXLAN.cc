// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/packet_analysis/protocol/vxlan/VXLAN.h"

#include "zeek/packet_analysis/protocol/iptunnel/IPTunnel.h"
#include "zeek/packet_analysis/protocol/vxlan/events.bif.h"

using namespace zeek::packet_analysis::VXLAN;

VXLAN_Analyzer::VXLAN_Analyzer() : zeek::packet_analysis::Analyzer("VXLAN") { }

bool VXLAN_Analyzer::AnalyzePacket(size_t len, const uint8_t* data, Packet* packet)
	{
	if ( packet->encap && packet->encap->Depth() >= BifConst::Tunnel::max_depth )
		{
		Weird("exceeded_tunnel_max_depth", packet);
		return false;
		}

	constexpr uint16_t hdr_size = 8;

	if ( hdr_size > len )
		{
		AnalyzerViolation("VXLAN header truncation", packet->session, (const char*)data, len);
		return false;
		}

	if ( (data[0] & 0x08) == 0 )
		{
		AnalyzerViolation("VXLAN 'I' flag not set", packet->session, (const char*)data, len);
		return false;
		}

	int vni = (data[4] << 16) + (data[5] << 8) + (data[6] << 0);

	len -= hdr_size;
	data += hdr_size;

	int encap_index = 0;
	auto inner_packet = packet_analysis::IPTunnel::build_inner_packet(
		packet, &encap_index, nullptr, len, data, DLT_RAW, BifEnum::Tunnel::VXLAN,
		GetAnalyzerTag());

	bool fwd_ret_val = true;
	if ( len > hdr_size )
		fwd_ret_val = ForwardPacket(len, data, inner_packet.get());

	if ( fwd_ret_val )
		{
		AnalyzerConfirmation(packet->session);

		if ( vxlan_packet && packet->session )
			{
			EncapsulatingConn* ec = inner_packet->encap->At(encap_index);
			if ( ec && ec->ip_hdr )
				inner_packet->session->EnqueueEvent(vxlan_packet, nullptr,
				                                    packet->session->GetVal(),
				                                    ec->ip_hdr->ToPktHdrVal(), val_mgr->Count(vni));
			}
		}
	else
		AnalyzerViolation("VXLAN invalid inner packet", packet->session);

	return fwd_ret_val;
	}
