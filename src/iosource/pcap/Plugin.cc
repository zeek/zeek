// See the file  in the main distribution directory for copyright.

#include "Source.h"
#include "Dumper.h"
#include "plugin/Plugin.h"
#include "iosource/Component.h"

namespace plugin {
namespace Zeek_Pcap {

class Plugin : public zeek::plugin::Plugin {
public:
	zeek::plugin::Configuration Configure() override
		{
		AddComponent(new ::iosource::PktSrcComponent("PcapReader", "pcap", ::iosource::PktSrcComponent::BOTH, ::iosource::pcap::PcapSource::Instantiate));
		AddComponent(new ::iosource::PktDumperComponent("PcapWriter", "pcap", ::iosource::pcap::PcapDumper::Instantiate));

		zeek::plugin::Configuration config;
		config.name = "Zeek::Pcap";
		config.description = "Packet acquisition via libpcap";
		return config;
		}
} plugin;

}
}
