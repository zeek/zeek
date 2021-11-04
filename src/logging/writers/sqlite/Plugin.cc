// See the file  in the main distribution directory for copyright.

#include "zeek/plugin/Plugin.h"

#include "zeek/logging/writers/sqlite/SQLite.h"

namespace zeek::plugin::detail::Zeek_SQLiteWriter
	{

class Plugin : public zeek::plugin::Plugin
	{
public:
	zeek::plugin::Configuration Configure() override
		{
		AddComponent(new zeek::logging::Component(
			"SQLite", zeek::logging::writer::detail::SQLite::Instantiate));

		zeek::plugin::Configuration config;
		config.name = "Zeek::SQLiteWriter";
		config.description = "SQLite log writer";
		return config;
		}
	} plugin;

	} // namespace zeek::plugin::detail::Zeek_SQLiteWriter
