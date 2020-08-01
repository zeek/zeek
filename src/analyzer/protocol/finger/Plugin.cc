// See the file  in the main distribution directory for copyright.

#include "Finger.h"
#include "plugin/Plugin.h"
#include "analyzer/Component.h"

namespace plugin {
namespace Zeek_Finger {

class Plugin : public zeek::plugin::Plugin {
public:
	zeek::plugin::Configuration Configure() override
		{
		AddComponent(new zeek::analyzer::Component("Finger", ::analyzer::finger::Finger_Analyzer::Instantiate));

		zeek::plugin::Configuration config;
		config.name = "Zeek::Finger";
		config.description = "Finger analyzer";
		return config;
		}
} plugin;

}
}
