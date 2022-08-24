// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/plugin/Plugin.h"

#include "zeek/packet_analysis/Component.h"
#include "zeek/packet_analysis/protocol/linux_sll2/LinuxSLL2.h"

namespace zeek::plugin::Zeek_LinuxSLL2
	{

class Plugin : public zeek::plugin::Plugin
	{
public:
	zeek::plugin::Configuration Configure()
		{
		AddComponent(new zeek::packet_analysis::Component(
			"LinuxSLL2", zeek::packet_analysis::LinuxSLL2::LinuxSLL2Analyzer::Instantiate));

		zeek::plugin::Configuration config;
		config.name = "Zeek::LinuxSLL2";
		config.description = "Linux cooked capture version 2 (SLL2) packet analyzer";
		return config;
		}

	} plugin;

	}
