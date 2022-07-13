
#pragma once

#include <plugin/Plugin.h>

namespace btest::plugin::Demo_Unprocessed_Packet
	{

class Plugin : public zeek::plugin::Plugin
	{
protected:
	void HookUnprocessedPacket(const zeek::Packet* packet) override;

	// Overridden from zeek::plugin::Plugin.
	zeek::plugin::Configuration Configure() override;
	};

extern Plugin plugin;

	}
