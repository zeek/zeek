// See the file  in the main distribution directory for copyright.


#include "plugin/Plugin.h"

#include "SQLite.h"

namespace plugin {
namespace Bro_SQLiteWriter {

class Plugin : public plugin::Plugin {
public:
	plugin::Configuration Configure()
		{
		AddComponent(new ::logging::Component("SQLite", ::logging::writer::SQLite::Instantiate));

		plugin::Configuration config;
		config.name = "Bro::SQLiteWriter";
		config.description = "SQLite log writer";
		return config;
		}
} plugin;

}
}
