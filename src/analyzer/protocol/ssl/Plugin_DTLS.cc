// See the file  in the main distribution directory for copyright.


#include "plugin/Plugin.h"

#include "DTLS.h"

namespace plugin {
namespace Bro_DTLS {

class Plugin : public plugin::Plugin {
public:
	plugin::Configuration Configure()
		{
		AddComponent(new ::analyzer::Component("DTLS", ::analyzer::dtls::DTLS_Analyzer::Instantiate));

		plugin::Configuration config;
		config.name = "Bro::DTLS";
		config.description = "DTLS analyzer";
		return config;
		}
} plugin;

}
}

