// See the file "COPYING" in the main distribution directory for copyright.

#include "NFLog.h"
#include "NetVar.h"

using namespace zeek::packet_analysis::NFLog;

NFLogAnalyzer::NFLogAnalyzer()
	: zeek::packet_analysis::Analyzer("NFLog")
	{
	}

zeek::packet_analysis::AnalysisResultTuple NFLogAnalyzer::Analyze(Packet* packet) {
	auto& pdata = packet->cur_pos;
	auto end_of_data = packet->GetEndOfData();

	// See https://www.tcpdump.org/linktypes/LINKTYPE_NFLOG.html
	uint32_t protocol = pdata[0];
	uint8_t version = pdata[1];

	if ( version != 0 )
		{
		packet->Weird("unknown_nflog_version");
		return { AnalyzerResult::Failed, 0 };
		}

	// Skip to TLVs.
	pdata += 4;

	uint16_t tlv_len;
	uint16_t tlv_type;

	while ( true )
		{
		if ( pdata + 4 >= end_of_data )
			{
			packet->Weird("nflog_no_pcap_payload");
			return { AnalyzerResult::Failed, 0 };
			}

		// TLV Type and Length values are specified in host byte order
		// (libpcap should have done any needed byteswapping already).

		tlv_len = *(reinterpret_cast<const uint16_t*>(pdata));
		tlv_type = *(reinterpret_cast<const uint16_t*>(pdata + 2));

		auto constexpr nflog_type_payload = 9;

		if ( tlv_type == nflog_type_payload )
			{
			// The raw packet payload follows this TLV.
			pdata += 4;
			break;
			}
		else
			{
			// The Length value includes the 4 octets for the Type and
			// Length values, but TLVs are also implicitly padded to
			// 32-bit alignments (that padding may not be included in
			// the Length value).

			if ( tlv_len < 4 )
				{
				packet->Weird("nflog_bad_tlv_len");
				return { AnalyzerResult::Failed, 0 };
				}
			else
				{
				auto rem = tlv_len % 4;

				if ( rem != 0 )
					tlv_len += 4 - rem;
				}

			pdata += tlv_len;
			}
		}

	return { AnalyzerResult::Continue, protocol };
	}
