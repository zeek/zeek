
#include "Plugin.h"
#include "llanalyzer/Component.h"

#include "Bar.h"

namespace zeek::plugin::LLDemo_Bar {

class Plugin : public zeek::plugin::Plugin {
public:
	zeek::plugin::Configuration Configure()
		{
		AddComponent(new zeek::llanalyzer::Component("Bar",
		                 zeek::llanalyzer::LLDemo::Bar::Instantiate));

		zeek::plugin::Configuration config;
		config.name = "LLDemo::Bar";
		config.description = "A Bar LL-test-analyzer.";
		config.version.major = 1;
		config.version.minor = 0;
		config.version.patch = 0;
		return config;
		}

} plugin;

}
