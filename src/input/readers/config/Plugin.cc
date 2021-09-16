// See the file  in the main distribution directory for copyright.

#include "zeek/plugin/Plugin.h"

#include "zeek/input/readers/config/Config.h"

namespace zeek::plugin::detail::Zeek_ConfigReader
	{

class Plugin : public zeek::plugin::Plugin
	{
public:
	zeek::plugin::Configuration Configure() override
		{
		AddComponent(
			new zeek::input::Component("Config", zeek::input::reader::detail::Config::Instantiate));

		zeek::plugin::Configuration config;
		config.name = "Zeek::ConfigReader";
		config.description = "Configuration file input reader";
		return config;
		}
	} plugin;

	} // namespace zeek::plugin::detail::Zeek_ConfigReader
