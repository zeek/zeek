// See the file  in the main distribution directory for copyright.


#include "plugin/Plugin.h"

namespace plugin {
namespace Zeek_ARP {

class Plugin : public zeek::plugin::Plugin {
public:
	zeek::plugin::Configuration Configure() override
		{
		zeek::plugin::Configuration config;
		config.name = "Zeek::ARP";
		config.description = "ARP Parsing";
		return config;
		}
} plugin;

}
}
