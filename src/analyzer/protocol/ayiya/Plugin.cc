// See the file  in the main distribution directory for copyright.

#include "AYIYA.h"
#include "plugin/Plugin.h"
#include "analyzer/Component.h"

namespace plugin {
namespace Zeek_AYIYA {

class Plugin : public zeek::plugin::Plugin {
public:
	zeek::plugin::Configuration Configure() override
		{
		AddComponent(new zeek::analyzer::Component("AYIYA", ::analyzer::ayiya::AYIYA_Analyzer::Instantiate));

		zeek::plugin::Configuration config;
		config.name = "Zeek::AYIYA";
		config.description = "AYIYA Analyzer";
		return config;
		}
} plugin;

}
}
