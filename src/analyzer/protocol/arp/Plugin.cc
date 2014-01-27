// See the file  in the main distribution directory for copyright.


#include "plugin/Plugin.h"

namespace plugin {
namespace Bro_ARP {

class Plugin : public plugin::Plugin {
public:
	plugin::Configuration Configure()
		{
		plugin::Configuration config;
		config.name = "Bro::ARP";
		config.description = "ARP Parsing";
		return config;
		}
} plugin;

}
}
