
#include "Plugin.h"

#include <Conn.h>
#include <Desc.h>
#include <Event.h>
#include <Func.h>
#include <RunState.h>
#include <threading/Formatter.h>

namespace btest::plugin::Demo_Unprocessed_Packet
	{
Plugin plugin;
	}

using namespace btest::plugin::Demo_Unprocessed_Packet;

zeek::plugin::Configuration Plugin::Configure()
	{
	EnableHook(zeek::plugin::HOOK_UNPROCESSED_PACKET);

	zeek::plugin::Configuration config;
	config.name = "Demo::Unprocessed_Packet";
	config.description = "Exercises all plugin hooks";
	config.version.major = 1;
	config.version.minor = 0;
	config.version.patch = 0;
	return config;
	}

void Plugin::HookUnprocessedPacket(const zeek::Packet* packet)
	{
	zeek::ODesc d;
	d.Add("[");
	d.Add("ts=");
	d.Add(packet->time);
	d.Add(" len=");
	d.Add(packet->len);
	d.Add("]");

	fprintf(stdout, "%.6f %-23s %s\n", zeek::run_state::network_time, "| HookUnprocessedPacket",
	        d.Description());
	}
