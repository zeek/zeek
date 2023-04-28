// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/packet_analysis/protocol/llc/LLC.h"

using namespace zeek::packet_analysis::LLC;

LLCAnalyzer::LLCAnalyzer() : zeek::packet_analysis::Analyzer("LLC") { }

bool LLCAnalyzer::AnalyzePacket(size_t len, const uint8_t* data, Packet* packet)
	{
	// An LLC header is at least 3 bytes, check for that first.
	if ( len < 3 )
		{
		Weird("truncated_llc_header", packet);
		return false;
		}

	// If the control field doesn't have an unnumbered PDU, the header is actually 4
	// bytes long. Whether this is unnumbered is denoted by the last two bits being
	// set.
	size_t llc_header_len = 3;
	if ( (data[2] & 0x03) != 0x03 )
		llc_header_len++;

	if ( len < llc_header_len )
		{
		Weird("truncated_llc_header", packet);
		return false;
		}

	// The destination SAP should be the next protocol in the chain, so forward
	// based on that value. The DSAP is the first byte in header.
	return ForwardPacket(len, data, packet, data[0]);
	}
