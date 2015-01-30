// See the file  in the main distribution directory for copyright.


#include "plugin/Plugin.h"

#include "Syslog.h"

namespace plugin {
namespace Bro_Syslog {

class Plugin : public plugin::Plugin {
public:
	plugin::Configuration Configure()
		{
		AddComponent(new ::analyzer::Component("Syslog", ::analyzer::syslog::Syslog_Analyzer::Instantiate));

		plugin::Configuration config;
		config.name = "Bro::Syslog";
		config.description = "Syslog analyzer UDP-only";
		return config;
		}
} plugin;

}
}
