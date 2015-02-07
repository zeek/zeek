// See the file  in the main distribution directory for copyright.


#include "plugin/Plugin.h"

#include "SIP.h"

namespace plugin {
namespace Bro_SIP {

class Plugin : public plugin::Plugin {
public:
	plugin::Configuration Configure()
		{
		AddComponent(new ::analyzer::Component("SIP", ::analyzer::SIP::SIP_Analyzer::Instantiate));

		plugin::Configuration config;
		config.name = "Bro::SIP";
		config.description = "SIP analyzer";
		return config;
		}
} plugin;

}
}
