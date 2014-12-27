// See the file  in the main distribution directory for copyright.


#include "plugin/Plugin.h"

#include "NTP.h"

namespace plugin {
namespace Bro_NTP {

class Plugin : public plugin::Plugin {
public:
	plugin::Configuration Configure()
		{
		AddComponent(new ::analyzer::Component("NTP", ::analyzer::ntp::NTP_Analyzer::Instantiate));

		plugin::Configuration config;
		config.name = "Bro::NTP";
		config.description = "NTP analyzer";
		return config;
		}
} plugin;

}
}
