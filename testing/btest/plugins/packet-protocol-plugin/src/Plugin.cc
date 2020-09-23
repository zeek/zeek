#include "Plugin.h"
#include "packet_analysis/Component.h"

#include "RawLayer.h"
#include "LLCDemo.h"

namespace zeek::plugin::PacketDemo_Bar {

class Plugin : public zeek::plugin::Plugin {
public:
	zeek::plugin::Configuration Configure()
		{
		AddComponent(new zeek::packet_analysis::Component("Raw_Layer",
		                 zeek::packet_analysis::PacketDemo::RawLayer::Instantiate));
		AddComponent(new zeek::packet_analysis::Component("LLC_Demo",
		                 zeek::packet_analysis::PacketDemo::LLCDemo::Instantiate));

		zeek::plugin::Configuration config;
		config.name = "PacketDemo::Bar";
		config.description = "Demo packet analyzers (RawLayer, LLC).";
		config.version.major = 1;
		config.version.minor = 0;
		config.version.patch = 0;
		return config;
		}

} plugin;

}
