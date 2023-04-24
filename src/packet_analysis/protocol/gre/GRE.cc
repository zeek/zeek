// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/packet_analysis/protocol/gre/GRE.h"

#include <pcap.h> // For DLT_ constants

#include "zeek/IP.h"
#include "zeek/Reporter.h"
#include "zeek/RunState.h"
#include "zeek/session/Manager.h"

using namespace zeek::packet_analysis::GRE;

static unsigned int gre_header_len(uint16_t flags = 0)
	{
	unsigned int len = 4; // Always has 2 byte flags and 2 byte protocol type.

	if ( flags & 0x8000 )
		// Checksum/Reserved1 present.
		len += 4;

	// Not considering routing presence bit since it's deprecated ...

	if ( flags & 0x2000 )
		// Key present.
		len += 4;

	if ( flags & 0x1000 )
		// Sequence present.
		len += 4;

	if ( flags & 0x0080 )
		// Acknowledgement present.
		len += 4;

	return len;
	}

GREAnalyzer::GREAnalyzer() : zeek::packet_analysis::Analyzer("GRE") { }

bool GREAnalyzer::AnalyzePacket(size_t len, const uint8_t* data, Packet* packet)
	{
	if ( ! packet->ip_hdr )
		{
		reporter->InternalError("GREAnalyzer: ip_hdr not provided from earlier analyzer");
		return false;
		}

	if ( ! BifConst::Tunnel::enable_gre )
		{
		Weird("GRE_tunnel", packet);
		return false;
		}

	if ( len < gre_header_len() )
		{
		Weird("truncated_GRE", packet);
		return false;
		}

	int proto = packet->proto;
	int gre_link_type = DLT_RAW;

	uint16_t flags_ver = ntohs(*((uint16_t*)(data + 0)));
	uint16_t proto_typ = ntohs(*((uint16_t*)(data + 2)));
	int gre_version = flags_ver & 0x0007;

	unsigned int eth_len = 0;
	unsigned int gre_len = gre_header_len(flags_ver);
	unsigned int pptp_len = gre_version == 1 ? 4 : 0;
	unsigned int erspan_len = 0;

	if ( gre_version != 0 && gre_version != 1 )
		{
		Weird("unknown_gre_version", packet, util::fmt("version=%d", gre_version));
		return false;
		}

	if ( gre_version == 0 )
		{
		if ( proto_typ == 0x6558 )
			{
			// transparent ethernet bridging
			if ( len > gre_len + 14 )
				{
				eth_len = 14;
				gre_link_type = DLT_EN10MB;
				}
			else
				{
				Weird("truncated_GRE", packet);
				return false;
				}
			}

		else if ( proto_typ == 0x88be )
			{
			if ( len > gre_len + 14 )
				{
				// ERSPAN type I
				erspan_len = 0;
				eth_len = 14;
				gre_link_type = DLT_EN10MB;
				bool have_sequence_header = ((flags_ver & 0x1000) == 0x1000);
				if ( have_sequence_header )
					{
					// ERSPAN type II
					erspan_len += 8;
					if ( len < gre_len + eth_len + erspan_len )
						{
						Weird("truncated_GRE", packet);
						return false;
						}
					}
				}
			else
				{
				Weird("truncated_GRE", packet);
				return false;
				}
			}

		else if ( proto_typ == 0x22eb )
			{
			// ERSPAN type III
			if ( len > gre_len + 14 + 12 )
				{
				erspan_len = 12;
				eth_len = 14;
				gre_link_type = DLT_EN10MB;

				auto flags = data + gre_len + erspan_len - 1;
				bool have_opt_header = ((*flags & 0x01) == 0x01);

				if ( have_opt_header )
					{
					if ( len > gre_len + erspan_len + 8 + eth_len )
						erspan_len += 8;
					else
						{
						Weird("truncated_GRE", packet);
						return false;
						}
					}
				}
			else
				{
				Weird("truncated_GRE", packet);
				return false;
				}
			}
		else if ( ((proto_typ & 0x8200) == 0x8200 && (proto_typ & 0x0F) == 0) ||
		          ((proto_typ & 0x8300) == 0x8300 && (proto_typ & 0x0F) == 0 &&
		           (proto_typ <= 0x8370)) ||
		          (proto_typ == 0x9000) )
			{
			// ARUBA: Set gre_link_type to IEEE802.11 so the IPTUNNEL analyzer uses
			// that to instantiate the fake tunnel packet, otherwise it'd be using
			// DLT_RAW which is not correct for ARUBA.
			if ( len <= gre_len )
				{
				Weird("truncated_GRE", packet);
				return false;
				}

			gre_link_type = DLT_IEEE802_11;
			proto = proto_typ;
			}
		else
			{
			// Otherwise let the packet analysis forwarding handle it.
			proto = proto_typ;
			}
		}

	else // gre_version == 1
		{
		if ( proto_typ != 0x880b )
			{
			// Enhanced GRE payload must be PPTP.
			Weird("egre_protocol_type", packet, util::fmt("proto=%d", proto_typ));
			return false;
			}
		}

	if ( flags_ver & 0x4000 )
		{
		// RFC 2784 deprecates the variable length routing field specified by RFC 1701. It could be
		// parsed here, but easiest to just skip for now.
		Weird("gre_routing", packet);
		return false;
		}

	if ( flags_ver & 0x0078 )
		{
		// Expect last 4 bits of flags are reserved, undefined.
		Weird("unknown_gre_flags", packet);
		return false;
		}

	if ( len < gre_len + pptp_len + eth_len + erspan_len )
		{
		Weird("truncated_GRE", packet);
		return false;
		}

	// For GRE version 1/PPTP, reset the protocol based on a value from the PPTP header.
	// TODO: where are these two values defined?
	if ( gre_version == 1 )
		{
		uint16_t pptp_proto = ntohs(*((uint16_t*)(data + gre_len + 2)));

		if ( pptp_proto != 0x0021 && pptp_proto != 0x0057 )
			{
			Weird("non_ip_packet_in_encap", packet);
			return false;
			}

		proto = (pptp_proto == 0x0021) ? IPPROTO_IPV4 : IPPROTO_IPV6;
		}

	data += gre_len + pptp_len + erspan_len;
	len -= gre_len + pptp_len + erspan_len;

	// Treat GRE tunnel like IP tunnels, fallthrough to logic below now that GRE header is stripped
	// and only payload packet remains.  The only thing different is the tunnel type enum value to
	// use.
	packet->tunnel_type = BifEnum::Tunnel::GRE;
	packet->gre_version = gre_version;
	packet->gre_link_type = gre_link_type;
	packet->proto = proto;

	// This will default to forwarding into IP Tunnel unless something custom is set up.
	ForwardPacket(len, data, packet, proto);

	return true;
	}
