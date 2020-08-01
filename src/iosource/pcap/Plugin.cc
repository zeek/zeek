// See the file  in the main distribution directory for copyright.

#include "Source.h"
#include "Dumper.h"
#include "plugin/Plugin.h"
#include "iosource/Component.h"

namespace zeek::plugin::Zeek_Pcap {

class Plugin : public zeek::plugin::Plugin {
public:
	zeek::plugin::Configuration Configure() override
		{
		AddComponent(new zeek::iosource::PktSrcComponent(
			             "PcapReader", "pcap", zeek::iosource::PktSrcComponent::BOTH,
			             zeek::iosource::pcap::PcapSource::Instantiate));
		AddComponent(new zeek::iosource::PktDumperComponent(
			             "PcapWriter", "pcap", zeek::iosource::pcap::PcapDumper::Instantiate));

		zeek::plugin::Configuration config;
		config.name = "Zeek::Pcap";
		config.description = "Packet acquisition via libpcap";
		return config;
		}
} plugin;

} // namespace zeek::plugin::Zeek_Pcap
