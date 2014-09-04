// See the file  in the main distribution directory for copyright.


#include "plugin/Plugin.h"

#include "BackDoor.h"

namespace plugin {
namespace Bro_BackDoor {

class Plugin : public plugin::Plugin {
public:
	plugin::Configuration Configure()
		{
		AddComponent(new ::analyzer::Component("BackDoor", ::analyzer::backdoor::BackDoor_Analyzer::Instantiate));

		plugin::Configuration config;
		config.name = "Bro::BackDoor";
		config.description = "Backdoor Analyzer deprecated";
		return config;
		}
} plugin;

}
}
