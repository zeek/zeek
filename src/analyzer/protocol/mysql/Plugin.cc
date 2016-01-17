// See the file "COPYING" in the main distribution directory for copyright.

#include "plugin/Plugin.h"

#include "MySQL.h"

namespace plugin {
	namespace Bro_MySQL {
		class Plugin : public plugin::Plugin {
		public:
			plugin::Configuration Configure()
				{
				AddComponent(new ::analyzer::Component("MySQL", ::analyzer::MySQL::MySQL_Analyzer::Instantiate));
				plugin::Configuration config;
				config.name = "Bro::MySQL";
				config.description = "MySQL analyzer";
				return config;
				}
		} plugin;
	}
}
