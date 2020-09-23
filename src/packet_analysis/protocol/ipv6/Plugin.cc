// See the file "COPYING" in the main distribution directory for copyright.

#include "plugin/Plugin.h"
#include "IPv6.h"
#include "packet_analysis/Component.h"

namespace zeek::plugin::Zeek_IPv6 {

class Plugin : public zeek::plugin::Plugin {
public:
	zeek::plugin::Configuration Configure()
		{
		AddComponent(new zeek::packet_analysis::Component("IPv6",
		             zeek::packet_analysis::IPv6::IPv6Analyzer::Instantiate));

		zeek::plugin::Configuration config;
		config.name = "Zeek::IPv6";
		config.description = "IPv6 packet analyzer";
		return config;
		}
} plugin;

}
