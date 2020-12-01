#include "LLCDemo.h"
#include "zeek/Event.h"
#include "zeek/Val.h"
#include "zeek/Sessions.h"
#include "events.bif.h"

using namespace zeek::packet_analysis::PacketDemo;

LLCDemo::LLCDemo()
	: zeek::packet_analysis::Analyzer("LLC_Demo")
	{
	}

bool LLCDemo::AnalyzePacket(size_t len, const uint8_t* data, Packet* packet)
	{
	// Rudimentary parsing of 802.2 LLC
	if ( 17 >= len )
		{
		sessions->Weird("truncated_llc_header", packet);
		return false;
		}

	auto dsap = data[14];
	auto ssap = data[15];
	auto control = data[16];

	event_mgr.Enqueue(llc_demo_message,
		val_mgr->Count(dsap),
		val_mgr->Count(ssap),
		val_mgr->Count(control));

	return true;
	}
