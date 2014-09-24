// See the file  in the main distribution directory for copyright.

#include "plugin/Plugin.h"

#include "Finger.h"

namespace plugin {
namespace Bro_Finger {

class Plugin : public plugin::Plugin {
public:
	plugin::Configuration Configure()
		{
		AddComponent(new ::analyzer::Component("Finger", ::analyzer::finger::Finger_Analyzer::Instantiate));

		plugin::Configuration config;
		config.name = "Bro::Finger";
		config.description = "Finger analyzer";
		return config;
		}
} plugin;

}
}
