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
        AddComponent(new ::iosource::pktsrc::SourceComponent("PcapReader", "pcap", ::iosource::pktsrc::SourceComponent::BOTH, ::iosource::pktsrc::PcapSource::Instantiate));
        AddComponent(new ::iosource::pktsrc::DumperComponent("PcapWriter", "pcap", ::iosource::pktsrc::PcapDumper::Instantiate));

		plugin::Configuration config;
		config.name = "Bro::Pcap";
		config.description = "Packet aquisition via libpcap";
		return config;
		}
} plugin;

}
}

