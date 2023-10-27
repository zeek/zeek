// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/packet_analysis/protocol/ieee802_11/IEEE802_11.h"

using namespace zeek::packet_analysis::IEEE802_11;

IEEE802_11Analyzer::IEEE802_11Analyzer() : zeek::packet_analysis::Analyzer("IEEE802_11") { }

bool IEEE802_11Analyzer::AnalyzePacket(size_t len, const uint8_t* data, Packet* packet)
	{
	u_char len_80211 = 24; // minimal length of data frames

	if ( len_80211 >= len )
		{
		Weird("truncated_802_11_header", packet);
		return false;
		}

	u_char fc_80211 = data[0]; // Frame Control field
	bool is_amsdu = false;

	// Skip non-data frame types (management & control).
	if ( ! ((fc_80211 >> 2) & 0x02) )
		return false;

	// Skip subtypes without data.
	if ( (fc_80211 >> 4) & 0x04 )
		return false;

	// 'To DS' and 'From DS' flags set indicate use of the 4th address field.
	if ( (data[1] & 0x03) == 0x03 )
		len_80211 += packet->L2_ADDR_LEN;

	if ( len_80211 >= len )
		{
		Weird("truncated_802_11_header", packet);
		return false;
		}

	// Look for the QoS indicator bit.
	if ( (fc_80211 >> 4) & 0x08 )
		{
		// Store off whether this is an A-MSDU header, which indicates that there are
		// mulitple packets following the 802.11 header.
		is_amsdu = (data[len_80211] & 0x80) == 0x80;

		// Check for the protected bit. This means the data is encrypted and we can't
		// do anything with it.
		if ( data[1] & 0x40 )
			return true;

		len_80211 += 2;
		}

	if ( len_80211 >= len )
		{
		Weird("truncated_802_11_header", packet);
		return false;
		}

	// Determine link-layer addresses based on 'To DS' and 'From DS' flags
	switch ( data[1] & 0x03 )
		{
		case 0x00:
			packet->l2_src = data + 10;
			packet->l2_dst = data + 4;
			break;

		case 0x01:
			packet->l2_src = data + 10;
			packet->l2_dst = data + 16;
			break;

		case 0x02:
			packet->l2_src = data + 16;
			packet->l2_dst = data + 4;
			break;

		case 0x03:
			packet->l2_src = data + 24;
			packet->l2_dst = data + 16;
			break;
		}

	// skip the 802.11 data header
	data += len_80211;
	len -= len_80211;

	if ( ! is_amsdu )
		{
		return HandleInnerPacket(len, data, packet);
		}
	else
		{
		size_t amsdu_padding = 0;
		size_t encap_index = packet->encap ? packet->encap->Depth() : 0;

		while ( len > 0 )
			{
			if ( len < 14 )
				{
				Weird("truncated_802_11_amsdu_header", packet);
				return false;
				}

			// This is the length of everything after the A-MSDU subframe header.
			size_t amsdu_len = (data[12] << 8) + data[13];
			if ( len < amsdu_len + 14 )
				{
				Weird("truncated_802_11_amsdu_packet", packet);
				return false;
				}

			// Skip the A-MSDU subframe header. This should place us at the start of an LLC header.
			data += 14;
			len -= 14;

			if ( ! HandleInnerPacket(amsdu_len, data, packet) )
				{
				Weird("invalid_802_11_amsdu_inner_packet", packet);
				return false;
				}

			data += amsdu_len;
			len -= amsdu_len;

			// Each A-MSDU subframe is padded by up to 3 bytes to make a multiple of 4. This padding
			// isn't included in the length field value. The padding also doesn't happen with the
			// last subframe, so check to see that we can even subtract it. Unfortunately, there
			// isn't a frame counter in the header so we just have trust that it all works out.
			amsdu_padding = amsdu_len % 4;
			if ( len >= amsdu_padding )
				{
				data += amsdu_padding;
				len -= amsdu_padding;
				}

			// Pop encapsuations back up to the level where we started processing so that the next
			// subframe gets the same encapsulation stack.
			if ( packet->encap )
				{
				while ( packet->encap->Depth() > encap_index )
					packet->encap->Pop();
				}
			}

		return true;
		}
	}

bool IEEE802_11Analyzer::HandleInnerPacket(size_t len, const uint8_t* data, Packet* packet) const
	{
	// Make sure there's room for an LLC header.
	if ( len < 8 )
		{
		Weird("truncated_802_11_llc_header", packet);
		return false;
		}

	// Check that the DSAP and SSAP are both SNAP and that the control field indicates that this is
	// an unnumbered frame.  The organization code (24bits) needs to also be zero to indicate that
	// this is encapsulated ethernet.
	if ( data[0] == 0xAA && data[1] == 0xAA && data[2] == 0x03 && data[3] == 0 && data[4] == 0 &&
	     data[5] == 0 )
		{
		data += 6;
		len -= 6;
		}
	else
		{
		// If this is a logical link control frame without the possibility of having a protocol we
		// care about, we'll just skip it for now.
		return false;
		}

	// Get the protocol and skip the rest of the LLC header.
	uint32_t protocol = (data[0] << 8) + data[1];
	data += 2;
	len -= 2;

	return ForwardPacket(len, data, packet, protocol);
	}
