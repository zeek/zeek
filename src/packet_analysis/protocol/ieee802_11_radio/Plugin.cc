// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/plugin/Plugin.h"

#include "zeek/packet_analysis/Component.h"
#include "zeek/packet_analysis/protocol/ieee802_11_radio/IEEE802_11_Radio.h"

namespace zeek::plugin::Zeek_IEEE802_11_Radio
	{

class Plugin : public zeek::plugin::Plugin
	{
public:
	zeek::plugin::Configuration Configure()
		{
		AddComponent(new zeek::packet_analysis::Component(
			"IEEE802_11_Radio",
			zeek::packet_analysis::IEEE802_11_Radio::IEEE802_11_RadioAnalyzer::Instantiate));

		zeek::plugin::Configuration config;
		config.name = "Zeek::IEEE802_11_Radio";
		config.description = "IEEE 802.11 Radiotap packet analyzer";
		return config;
		}

	} plugin;
	}
