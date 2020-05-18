// See the file in the main distribution directory for copyright.

#include "plugin/Plugin.h"

#include "GSSAPI.h"

namespace plugin {
namespace Zeek_GSSAPI {

class Plugin : public plugin::Plugin {
public:
	plugin::Configuration Configure() override
		{
		AddComponent(new ::analyzer::Component("GSSAPI", ::analyzer::gssapi::GSSAPI_Analyzer::Instantiate));

		plugin::Configuration config;
		config.name = "Zeek::GSSAPI";
		config.description = "GSSAPI analyzer";
		return config;
		}
} plugin;

}
}
