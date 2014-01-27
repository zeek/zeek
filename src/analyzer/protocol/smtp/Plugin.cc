// See the file  in the main distribution directory for copyright.


#include "plugin/Plugin.h"

#include "SMTP.h"

namespace plugin {
namespace Bro_SMTP {

class Plugin : public plugin::Plugin {
public:
	plugin::Configuration Configure()
		{
		AddComponent(new ::analyzer::Component("SMTP", ::analyzer::smtp::SMTP_Analyzer::Instantiate));

		plugin::Configuration config;
		config.name = "Bro::SMTP";
		config.description = "SMTP analyzer";
		return config;
		}
} plugin;

}
}
