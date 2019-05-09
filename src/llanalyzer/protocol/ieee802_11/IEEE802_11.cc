// See the file "COPYING" in the main distribution directory for copyright.

#include "IEEE802_11.h"
#include "NetVar.h"

using namespace zeek::llanalyzer::IEEE802_11;

IEEE802_11Analyzer::IEEE802_11Analyzer()
	: zeek::llanalyzer::Analyzer("IEEE802_11")
	{
	}

std::tuple<zeek::llanalyzer::AnalyzerResult, zeek::llanalyzer::identifier_t> IEEE802_11Analyzer::Analyze(Packet* packet)
	{
	auto& pdata = packet->cur_pos;
	auto end_of_data = packet->GetEndOfData();

	u_char len_80211 = 24; // minimal length of data frames

	if ( pdata + len_80211 >= end_of_data )
		{
		packet->Weird("truncated_802_11_header");
		return { AnalyzerResult::Failed, 0 };
		}

	u_char fc_80211 = pdata[0]; // Frame Control field

	// Skip non-data frame types (management & control).
	if ( ! ((fc_80211 >> 2) & 0x02) )
		return { AnalyzerResult::Failed, 0 };

	// Skip subtypes without data.
	if ( (fc_80211 >> 4) & 0x04 )
		return { AnalyzerResult::Failed, 0 };

	// 'To DS' and 'From DS' flags set indicate use of the 4th
	// address field.
	if ( (pdata[1] & 0x03) == 0x03 )
		len_80211 += packet->L2_ADDR_LEN;

	// Look for the QoS indicator bit.
	if ( (fc_80211 >> 4) & 0x08 )
		{
		// Skip in case of A-MSDU subframes indicated by QoS
		// control field.
		if ( pdata[len_80211] & 0x80 )
			return { AnalyzerResult::Failed, 0 };

		len_80211 += 2;
		}

	if ( pdata + len_80211 >= end_of_data )
		{
		packet->Weird("truncated_802_11_header");
		return { AnalyzerResult::Failed, 0 };
		}

	// Determine link-layer addresses based
	// on 'To DS' and 'From DS' flags
	switch ( pdata[1] & 0x03 )
		{
		case 0x00:
			packet->l2_src = pdata + 10;
			packet->l2_dst = pdata + 4;
			break;

		case 0x01:
			packet->l2_src = pdata + 10;
			packet->l2_dst = pdata + 16;
			break;

		case 0x02:
			packet->l2_src = pdata + 16;
			packet->l2_dst = pdata + 4;
			break;

		case 0x03:
			packet->l2_src = pdata + 24;
			packet->l2_dst = pdata + 16;
			break;
		}

	// skip 802.11 data header
	pdata += len_80211;

	if ( pdata + 8 >= end_of_data )
		{
		packet->Weird("truncated_802_11_header");
		return { AnalyzerResult::Failed, 0 };
		}

	// Check that the DSAP and SSAP are both SNAP and that the control
	// field indicates that this is an unnumbered frame.
	// The organization code (24bits) needs to also be zero to
	// indicate that this is encapsulated ethernet.
	if ( pdata[0] == 0xAA && pdata[1] == 0xAA && pdata[2] == 0x03 &&
	     pdata[3] == 0 && pdata[4] == 0 && pdata[5] == 0 )
		{
		pdata += 6;
		}
	else
		{
		// If this is a logical link control frame without the
		// possibility of having a protocol we care about, we'll
		// just skip it for now.
		return { AnalyzerResult::Failed, 0 };
		}

	identifier_t protocol = (pdata[0] << 8) + pdata[1];
	pdata += 2;

	return { AnalyzerResult::Continue, protocol };
	}
