// See the file  in the main distribution directory for copyright.

#include "plugin/Plugin.h"

#include "Config.h"

namespace zeek::plugin::Zeek_ConfigReader {

class Plugin : public zeek::plugin::Plugin {
public:
	zeek::plugin::Configuration Configure() override
		{
		AddComponent(new zeek::input::Component("Config", zeek::input::reader::detail::Config::Instantiate));

		zeek::plugin::Configuration config;
		config.name = "Zeek::ConfigReader";
		config.description = "Configuration file input reader";
		return config;
		}
} plugin;

}
