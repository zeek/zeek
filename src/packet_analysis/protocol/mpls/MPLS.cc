// See the file "COPYING" in the main distribution directory for copyright.

#include "MPLS.h"

using namespace zeek::packet_analysis::MPLS;

MPLSAnalyzer::MPLSAnalyzer()
	: zeek::packet_analysis::Analyzer("MPLS")
	{
	}

zeek::packet_analysis::AnalysisResultTuple MPLSAnalyzer::Analyze(Packet* packet, const uint8_t*& data)
	{
	auto end_of_data = packet->GetEndOfData();

	// Skip the MPLS label stack.
	bool end_of_stack = false;

	while ( ! end_of_stack )
		{
		if ( data + 4 >= end_of_data )
			{
			packet->Weird("truncated_link_header");
			return { AnalyzerResult::Failed, 0 };
			}

		end_of_stack = *(data + 2u) & 0x01;
		data += 4;
		}

	// According to RFC3032 the encapsulated protocol is not encoded.
	// We assume that what remains is IP.
	if ( data + sizeof(struct ip) >= end_of_data )
		{
		packet->Weird("no_ip_in_mpls_payload");
		return { AnalyzerResult::Failed, 0 };
		}

	auto ip = (const struct ip*)data;

	if ( ip->ip_v == 4 )
		packet->l3_proto = L3_IPV4;
	else if ( ip->ip_v == 6 )
		packet->l3_proto = L3_IPV6;
	else
		{
		// Neither IPv4 nor IPv6.
		packet->Weird("no_ip_in_mpls_payload");
		return { AnalyzerResult::Failed, 0 };
		}

	packet->hdr_size = (data - packet->data);
	return { AnalyzerResult::Terminate, 0 };
	}
