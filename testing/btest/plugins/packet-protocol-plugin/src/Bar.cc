#include "Bar.h"
#include "Event.h"
#include "Val.h"
#include "events.bif.h"

using namespace zeek::packet_analysis::PacketDemo;

Bar::Bar()
	: zeek::packet_analysis::Analyzer("Bar")
	{
	}

bool Bar::AnalyzePacket(size_t len,
		const uint8_t* data, Packet* packet)
	{
	// Rudimentary parsing of 802.2 LLC
	if ( 17 >= len )
		{
		packet->Weird("truncated_llc_header");
		return false;
		}

	auto dsap = data[14];
	auto ssap = data[15];
	auto control = data[16];

	mgr.Enqueue(bar_message,
		val_mgr->Count(dsap),
		val_mgr->Count(ssap),
		val_mgr->Count(control));

	return true;
	}
