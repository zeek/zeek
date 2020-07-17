#include "Bar.h"
#include "Event.h"
#include "Val.h"
#include "events.bif.h"

using namespace zeek::packet_analysis::PacketDemo;

Bar::Bar()
	: zeek::packet_analysis::Analyzer("Bar")
	{
	}

zeek::packet_analysis::AnalysisResultTuple Bar::Analyze(Packet* packet, const uint8_t*& data)
	{
	auto end_of_data = packet->GetEndOfData();

	// Rudimentary parsing of 802.2 LLC
	if ( data + 17 >= end_of_data )
		{
		packet->Weird("truncated_llc_header");
		return { AnalyzerResult::Failed, 0 };
		}

	auto dsap = data[14];
	auto ssap = data[15];
	auto control = data[16];

	mgr.Enqueue(bar_message,
		val_mgr->Count(dsap),
		val_mgr->Count(ssap),
		val_mgr->Count(control));

	return { AnalyzerResult::Terminate, 0 };
	}
