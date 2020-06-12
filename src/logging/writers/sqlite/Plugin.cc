// See the file  in the main distribution directory for copyright.


#include "plugin/Plugin.h"

#include "SQLite.h"

namespace plugin {
namespace Zeek_SQLiteWriter {

class Plugin : public zeek::plugin::Plugin {
public:
	zeek::plugin::Configuration Configure() override
		{
		AddComponent(new ::logging::Component("SQLite", ::logging::writer::SQLite::Instantiate));

		zeek::plugin::Configuration config;
		config.name = "Zeek::SQLiteWriter";
		config.description = "SQLite log writer";
		return config;
		}
} plugin;

}
}
