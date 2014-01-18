// See the file  in the main distribution directory for copyright.


#include "plugin/Plugin.h"

#include "SSL.h"

namespace plugin {
namespace Bro_SSL {

class Plugin : public plugin::Plugin {
public:
	plugin::Configuration Configure()
		{
		AddComponent(new ::analyzer::Component("SSL", ::analyzer::ssl::SSL_Analyzer::Instantiate));

		plugin::Configuration config;
		config.name = "Bro::SSL";
		config.description = "SSL analyzer";
		return config;
		}
} plugin;

}
}
