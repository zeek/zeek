// See the file  in the main distribution directory for copyright.


#include "plugin/Plugin.h"

#include "BackDoor.h"

namespace plugin {
namespace Zeek_BackDoor {

class Plugin : public plugin::Plugin {
public:
	plugin::Configuration Configure()
		{
		AddComponent(new ::analyzer::Component("BackDoor", ::analyzer::backdoor::BackDoor_Analyzer::Instantiate));

		plugin::Configuration config;
		config.name = "Zeek::BackDoor";
		config.description = "Backdoor Analyzer deprecated";
		return config;
		}
} plugin;

}
}
