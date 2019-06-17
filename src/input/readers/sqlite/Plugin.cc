// See the file  in the main distribution directory for copyright.

#include "plugin/Plugin.h"

#include "SQLite.h"

namespace plugin {
namespace Zeek_SQLiteReader {

class Plugin : public plugin::Plugin {
public:
	plugin::Configuration Configure()
		{
		AddComponent(new ::input::Component("SQLite", ::input::reader::SQLite::Instantiate));

		plugin::Configuration config;
		config.name = "Zeek::SQLiteReader";
		config.description = "SQLite input reader";
		return config;
		}
} plugin;

}
}
