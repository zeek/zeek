// See the file  in the main distribution directory for copyright.

#include "zeek/plugin/Plugin.h"

#include "zeek/iosource/Component.h"
#include "zeek/iosource/pcap/Dumper.h"
#include "zeek/iosource/pcap/Source.h"

namespace zeek::plugin::detail::Zeek_Pcap
	{

class Plugin : public plugin::Plugin
	{
public:
	plugin::Configuration Configure() override
		{
		AddComponent(new iosource::PktSrcComponent("PcapReader", "pcap",
		                                           iosource::PktSrcComponent::BOTH,
		                                           iosource::pcap::PcapSource::Instantiate));
		AddComponent(new iosource::PktDumperComponent("PcapWriter", "pcap",
		                                              iosource::pcap::PcapDumper::Instantiate));

		plugin::Configuration config;
		config.name = "Zeek::Pcap";
		config.description = "Packet acquisition via libpcap";
		return config;
		}
	} plugin;

	} // namespace zeek::plugin::detail::Zeek_Pcap
