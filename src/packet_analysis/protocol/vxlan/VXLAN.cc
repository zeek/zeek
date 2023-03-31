// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/packet_analysis/protocol/vxlan/VXLAN.h"

#include "zeek/packet_analysis/protocol/iptunnel/IPTunnel.h"
#include "zeek/packet_analysis/protocol/vxlan/events.bif.h"

using namespace zeek::packet_analysis::VXLAN;

VXLAN_Analyzer::VXLAN_Analyzer() : zeek::packet_analysis::Analyzer("VXLAN") { }

bool VXLAN_Analyzer::AnalyzePacket(size_t len, const uint8_t* data, Packet* packet)
	{
	// VXLAN always comes from a UDP connection, which means that session should always
	// be valid and always be a connection. Return a weird if we didn't have a session
	// stored.
	if ( ! packet->session )
		{
		Analyzer::Weird("vxlan_missing_connection");
		return false;
		}
	else if ( AnalyzerViolated(packet->session) )
		return false;

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

	// We've successfully parsed the VXLAN part, so we might as well confirm this.
	AnalyzerConfirmation(packet->session);

	if ( len == 0 )
		{
		// A VXLAN header that isn't followed by a tunnelled packet seems weird.
		Weird("vxlan_empty_packet", packet);
		return false;
		}

	int encap_index = 0;
	auto inner_packet = packet_analysis::IPTunnel::build_inner_packet(
		packet, &encap_index, nullptr, len, data, DLT_RAW, BifEnum::Tunnel::VXLAN,
		GetAnalyzerTag());

	bool analysis_succeeded = ForwardPacket(len, data, inner_packet.get());

	if ( analysis_succeeded && vxlan_packet )
		{
		EncapsulatingConn* ec = inner_packet->encap->At(encap_index);
		if ( ec && ec->ip_hdr )
			inner_packet->session->EnqueueEvent(vxlan_packet, nullptr, packet->session->GetVal(),
			                                    ec->ip_hdr->ToPktHdrVal(), val_mgr->Count(vni));
		}

	return analysis_succeeded;
	}
