
#include "Plugin.h"
#include "packet_analysis/Component.h"

#include "Bar.h"

namespace zeek::plugin::PacketDemo_Bar {

class Plugin : public zeek::plugin::Plugin {
public:
	zeek::plugin::Configuration Configure()
		{
		AddComponent(new zeek::packet_analysis::Component("Bar",
		                 zeek::packet_analysis::PacketDemo::Bar::Instantiate));

		zeek::plugin::Configuration config;
		config.name = "PacketDemo::Bar";
		config.description = "A Bar packet analyzer.";
		config.version.major = 1;
		config.version.minor = 0;
		config.version.patch = 0;
		return config;
		}

} plugin;

}
