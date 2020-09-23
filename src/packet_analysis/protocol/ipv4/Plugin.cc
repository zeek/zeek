// See the file "COPYING" in the main distribution directory for copyright.

#include "IPv4.h"
#include "plugin/Plugin.h"
#include "packet_analysis/Component.h"

namespace zeek::plugin::Zeek_IPv4 {

class Plugin : public zeek::plugin::Plugin {
public:
	zeek::plugin::Configuration Configure()
		{
		AddComponent(new zeek::packet_analysis::Component("IPv4",
		                 zeek::packet_analysis::IPv4::IPv4Analyzer::Instantiate));

		zeek::plugin::Configuration config;
		config.name = "Zeek::IPv4";
		config.description = "IPv4 packet analyzer";
		return config;
		}

} plugin;

}
