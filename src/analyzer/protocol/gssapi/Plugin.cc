// See the file in the main distribution directory for copyright.

#include "plugin/Plugin.h"

#include "GSSAPI.h"

namespace plugin {
namespace Bro_GSSAPI {

class Plugin : public plugin::Plugin {
public:
	plugin::Configuration Configure()
		{
		AddComponent(new ::analyzer::Component("GSSAPI", ::analyzer::gssapi::GSSAPI_Analyzer::Instantiate));

		plugin::Configuration config;
		config.name = "Bro::GSSAPI";
		config.description = "GSSAPI analyzer";
		return config;
		}
} plugin;

}
}
