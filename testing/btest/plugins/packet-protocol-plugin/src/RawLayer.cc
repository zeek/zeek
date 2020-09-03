#include "RawLayer.h"
#include "Event.h"
#include "Val.h"
#include "events.bif.h"

using namespace zeek::packet_analysis::PacketDemo;

RawLayer::RawLayer()
	: zeek::packet_analysis::Analyzer("RawLayer")
	{
	}

bool RawLayer::AnalyzePacket(size_t len, const uint8_t* data, Packet* packet)
	{
	constexpr auto layer_size = 21;
	if ( layer_size >= len )
		{
		packet->Weird("truncated_raw_layer");
		return false;
		}

	uint16_t protocol = ntohs(*((const uint16_t*)(data + layer_size -2)));

	event_mgr.Enqueue(raw_layer_message,
		make_intrusive<StringVal>(layer_size, reinterpret_cast<const char*>(data)),
		val_mgr->Count(protocol));

	return ForwardPacket(len - layer_size, data + layer_size, packet, protocol);
	}
