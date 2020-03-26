// See the file  in the main distribution directory for copyright.


#include "plugin/Plugin.h"

namespace plugin {
namespace Zeek_ARP {

class Plugin : public plugin::Plugin {
public:
	plugin::Configuration Configure() override
		{
		plugin::Configuration config;
		config.name = "Zeek::ARP";
		config.description = "ARP Parsing";
		return config;
		}
} plugin;

}
}
