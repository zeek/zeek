// See the file  in the main distribution directory for copyright.

#include "zeek/plugin/Plugin.h"

#include "zeek/input/readers/sqlite/SQLite.h"

namespace zeek::plugin::detail::Zeek_SQLiteReader
	{

class Plugin : public zeek::plugin::Plugin
	{
public:
	zeek::plugin::Configuration Configure() override
		{
		AddComponent(
			new zeek::input::Component("SQLite", zeek::input::reader::detail::SQLite::Instantiate));

		zeek::plugin::Configuration config;
		config.name = "Zeek::SQLiteReader";
		config.description = "SQLite input reader";
		return config;
		}
	} plugin;

	} // namespace zeek::plugin::detail::Zeek_SQLiteReader
