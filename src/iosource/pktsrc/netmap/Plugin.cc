// See the file  in the main distribution directory for copyright.

#include "plugin/Plugin.h"

#include "Source.h"

namespace plugin {
namespace Bro_Netmap {

class Plugin : public plugin::Plugin {
public:
	plugin::Configuration Configure()
		{
		AddComponent(new ::iosource::pktsrc::SourceComponent("NetmapReader", "netmap", ::iosource::pktsrc::SourceComponent::LIVE, ::iosource::pktsrc::NetmapSource::InstantiateNetmap));
		AddComponent(new ::iosource::pktsrc::SourceComponent("NetmapReader", "vale", ::iosource::pktsrc::SourceComponent::LIVE, ::iosource::pktsrc::NetmapSource::InstantiateVale));

		plugin::Configuration config;
		config.name = "Bro::Netmap";
		config.description = "Packet aquisition via netmap";
		return config;
		}
} plugin;

}
}

