// See the file  in the main distribution directory for copyright.

#include "zeek/plugin/Plugin.h"

#include "zeek/input/readers/ascii/Ascii.h"

namespace zeek::plugin::detail::Zeek_AsciiReader
	{

class Plugin : public zeek::plugin::Plugin
	{
public:
	zeek::plugin::Configuration Configure() override
		{
		AddComponent(
			new zeek::input::Component("Ascii", zeek::input::reader::detail::Ascii::Instantiate));

		zeek::plugin::Configuration config;
		config.name = "Zeek::AsciiReader";
		config.description = "ASCII input reader";
		return config;
		}
	} plugin;

	} // namespace zeek::plugin::detail::Zeek_AsciiReader
