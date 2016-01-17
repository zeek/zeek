// See the file  in the main distribution directory for copyright.

#include "plugin/Plugin.h"

#include "Source.h"
#include "Dumper.h"

namespace plugin {
namespace Bro_Pcap {

class Plugin : public plugin::Plugin {
public:
	plugin::Configuration Configure()
		{
		AddComponent(new ::iosource::PktSrcComponent("PcapReader", "pcap", ::iosource::PktSrcComponent::BOTH, ::iosource::pcap::PcapSource::Instantiate));
		AddComponent(new ::iosource::PktDumperComponent("PcapWriter", "pcap", ::iosource::pcap::PcapDumper::Instantiate));

		plugin::Configuration config;
		config.name = "Bro::Pcap";
		config.description = "Packet acquisition via libpcap";
		return config;
		}
} plugin;

}
}

