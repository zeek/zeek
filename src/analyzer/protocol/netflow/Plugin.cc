// See the file  in the main distribution directory for copyright.


#include "plugin/Plugin.h"

namespace plugin {
namespace Bro_NetFlow {

class Plugin : public plugin::Plugin {
public:
	plugin::Configuration Configure()
		{
		plugin::Configuration config;
		config.name = "Bro::NetFlow";
		config.description = "NetFlow parsing";
		return config;
		}
} plugin;

}
}
