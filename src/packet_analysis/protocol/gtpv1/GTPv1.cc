// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/packet_analysis/protocol/gtpv1/GTPv1.h"

#include "zeek/packet_analysis/protocol/gtpv1/events.bif.h"
#include "zeek/packet_analysis/protocol/ip/IP.h"
#include "zeek/packet_analysis/protocol/iptunnel/IPTunnel.h"

namespace zeek::packet_analysis::gtpv1
	{
GTPv1_Analyzer::GTPv1_Analyzer() : zeek::packet_analysis::Analyzer("GTPV1") { }

bool GTPv1_Analyzer::AnalyzePacket(size_t len, const uint8_t* data, Packet* packet)
	{
	// GTPv1 always comes from a UDP connection, which means that session should always
	// be valid and always be a connection. Return a weird if we didn't have a session
	// stored.
	if ( ! packet->session )
		{
		Analyzer::Weird("gtpv1_missing_connection");
		return false;
		}

	auto conn = static_cast<Connection*>(packet->session);
	zeek::detail::ConnKey conn_key = conn->Key();

	auto cm_it = conn_map.find(conn_key);
	if ( cm_it == conn_map.end() )
		cm_it = conn_map.insert(cm_it,
		                        {conn_key, std::make_unique<binpac::GTPv1::GTPv1_Conn>(this)});

	try
		{
		cm_it->second->set_raw_packet(packet);
		cm_it->second->NewData(packet->is_orig, data, data + len);
		}
	catch ( const binpac::Exception& e )
		{
		AnalyzerViolation(util::fmt("Binpac exception: %s", e.c_msg()), packet->session);
		return false;
		}

	// Inner packet offset not being set means we failed to process somewhere, and SetInnerInfo()
	// was never called by the binpac code. Assume this is a failure and return false.
	if ( inner_packet_offset <= 0 )
		return false;

	auto odata = data;
	auto olen = len;
	data += inner_packet_offset;
	len -= inner_packet_offset;
	inner_packet_offset = -1;

	// TODO: i'm not sure about this. on the one hand, we do some error checking with the result
	// but on the other hand we duplicate this work here. maybe this header could just be stored
	// and reused in the IP analyzer somehow?
	std::shared_ptr<IP_Hdr> inner = nullptr;
	auto result = packet_analysis::IP::ParsePacket(len, data, next_header, inner);

	if ( result == packet_analysis::IP::ParseResult::Ok )
		{
		cm_it->second->set_valid(packet->is_orig, true);

		if ( (! BifConst::Tunnel::delay_gtp_confirmation) ||
		     (cm_it->second->valid(true) && cm_it->second->valid(false)) )
			AnalyzerConfirmation(packet->session);

		if ( gtp_hdr_val )
			{
			BifEvent::enqueue_gtpv1_g_pdu_packet(nullptr, conn, std::move(gtp_hdr_val),
			                                     inner->ToPktHdrVal());
			gtp_hdr_val = nullptr;
			}
		}
	else if ( result == packet_analysis::IP::ParseResult::BadProtocol )
		{
		AnalyzerViolation("Invalid IP version in wrapped packet", packet->session);
		gtp_hdr_val = nullptr;
		return false;
		}
	else if ( result == packet_analysis::IP::ParseResult::CaplenTooSmall )
		{
		AnalyzerViolation("Truncated GTPv1", packet->session);
		gtp_hdr_val = nullptr;
		return false;
		}
	else
		{
		AnalyzerViolation("GTPv1 payload length", packet->session);
		gtp_hdr_val = nullptr;
		return false;
		}

	int encap_index = 0;
	auto inner_packet = packet_analysis::IPTunnel::build_inner_packet(
		packet, &encap_index, nullptr, len, data, DLT_RAW, BifEnum::Tunnel::GTPv1,
		GetAnalyzerTag());

	return ForwardPacket(len, data, inner_packet.get());
	}

	} // namespace zeek::packet_analysis::gtpv1
