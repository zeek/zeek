// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/packet_analysis/protocol/geneve/Geneve.h"

#include "zeek/packet_analysis/protocol/geneve/events.bif.h"
#include "zeek/packet_analysis/protocol/iptunnel/IPTunnel.h"

using namespace zeek::packet_analysis::Geneve;

GeneveAnalyzer::GeneveAnalyzer() : zeek::packet_analysis::Analyzer("Geneve") { }

bool GeneveAnalyzer::AnalyzePacket(size_t len, const uint8_t* data, Packet* packet)
	{
	// Geneve always comes from a UDP connection, which means that session should always
	// be valid and always be a connection. Return a weird if we didn't have a session
	// stored.
	if ( ! packet->session )
		{
		Analyzer::Weird("geneve_missing_connection");
		return false;
		}
	else if ( AnalyzerViolated(packet->session) )
		return false;

	if ( packet->encap && packet->encap->Depth() >= BifConst::Tunnel::max_depth )
		{
		Weird("exceeded_tunnel_max_depth", packet);
		return false;
		}

	// This will be expanded based on the length of the options in the header,
	// but it will be at least this long.
	uint16_t hdr_size = 8;

	if ( hdr_size > len )
		{
		AnalyzerViolation("Geneve header truncation", packet->session,
		                  reinterpret_cast<const char*>(data), len);
		return false;
		}

	// Validate that the version number is correct. According to the RFC, this
	// should always be zero, and anything else should be treated as an error.
	auto version = data[0] >> 6;
	if ( version != 0 )
		{
		Weird("geneve_invalid_version", packet, util::fmt("%d", version));
		return false;
		}

	// Option length is the number of bytes for options, expressed in 4-byte multiples.
	uint8_t opt_len = (data[0] & 0x3F) * 4;
	hdr_size += opt_len;

	// Double-check this one now that we know the actual full length of the header.
	if ( hdr_size > len )
		{
		AnalyzerViolation("Geneve option header truncation", packet->session,
		                  reinterpret_cast<const char*>(data), len);
		return false;
		}

	// Get the next header. This will probably be Ethernet (0x6558), but get it
	// anyways so that the forwarding can do its thing.
	auto next_header = (data[2] << 8) + data[3];

	// Grab the VNI out of the data before advancing the data pointer
	auto vni = (data[4] << 16) + (data[5] << 8) + data[6];

	len -= hdr_size;
	data += hdr_size;

	// We've successfully parsed the Geneve part, so we might as well confirm this.
	AnalyzerConfirmation(packet->session);

	if ( len == 0 )
		{
		// A Geneve header that isn't followed by a tunnelled packet seems weird.
		Weird("geneve_empty_packet", packet);
		return false;
		}

	int encap_index = 0;
	auto inner_packet = packet_analysis::IPTunnel::build_inner_packet(
		packet, &encap_index, nullptr, len, data, DLT_RAW, BifEnum::Tunnel::GENEVE,
		GetAnalyzerTag());

	bool analysis_succeeded = ForwardPacket(len, data, inner_packet.get(), next_header);

	if ( analysis_succeeded && geneve_packet )
		{
		EncapsulatingConn* ec = inner_packet->encap->At(encap_index);
		if ( ec && ec->ip_hdr )
			inner_packet->session->EnqueueEvent(geneve_packet, nullptr, packet->session->GetVal(),
			                                    ec->ip_hdr->ToPktHdrVal(), val_mgr->Count(vni));
		}

	return analysis_succeeded;
	}
