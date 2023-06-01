// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/packet_analysis/protocol/snap/SNAP.h"

using namespace zeek::packet_analysis::SNAP;

SNAPAnalyzer::SNAPAnalyzer() : zeek::packet_analysis::Analyzer("SNAP") { }

bool SNAPAnalyzer::AnalyzePacket(size_t len, const uint8_t* data, Packet* packet)
	{
	// The first part of the header is an LLC header, which we need to determine the
	// length of the full header. Check to see if the shorter 3-byte version will fit.
	if ( len < 3 )
		{
		Weird("truncated_snap_llc_header", packet);
		return false;
		}

	// If the control field doesn't have an unnumbered PDU, the header is actually 4
	// bytes long. Whether this is unnumbered is denoted by the last two bits being
	// set.
	size_t llc_header_len = 3;
	if ( (data[2] & 0x03) != 0x03 )
		llc_header_len++;

	// Check the full length of the SNAP header, which is the LLC header plus 5 bytes.
	if ( len < llc_header_len + 5 )
		{
		Weird("truncated_snap_header", packet);
		return false;
		}

	data += llc_header_len;
	len -= llc_header_len;

	int oui = (data[0] << 16) | (data[1] << 8) | data[2];
	int protocol = (data[3] << 8) | data[4];

	data += 5;
	len -= 5;

	if ( oui == 0 )
		{
		// If the OUI is zero, the protocol is a standard ethertype and can be
		// forwarded as such.
		return ForwardPacket(len, data, packet, protocol);
		}

	return true;
	}
