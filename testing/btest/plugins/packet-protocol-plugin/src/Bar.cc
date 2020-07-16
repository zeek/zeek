#include "Bar.h"
#include "Event.h"
#include "Val.h"
#include "events.bif.h"

using namespace zeek::packet_analysis::PacketDemo;

Bar::Bar()
	: zeek::packet_analysis::Analyzer("Bar")
	{
	}

zeek::packet_analysis::AnalysisResultTuple Bar::Analyze(Packet* packet)
	{
	auto& pdata = packet->cur_pos;
	auto end_of_data = packet->GetEndOfData();

	// Rudimentary parsing of 802.2 LLC
	if ( pdata + 17 >= end_of_data )
		{
		packet->Weird("truncated_llc_header");
		return { AnalyzerResult::Failed, 0 };
		}

	auto dsap = pdata[14];
	auto ssap = pdata[15];
	auto control = pdata[16];

	mgr.Enqueue(bar_message,
		val_mgr->Count(dsap),
		val_mgr->Count(ssap),
		val_mgr->Count(control));

	return { AnalyzerResult::Terminate, 0 };
	}
