// See the file  in the main distribution directory for copyright.


#include "plugin/Plugin.h"

#include "SSL.h"
#include "DTLS.h"

namespace plugin {
namespace Bro_SSL {

class Plugin : public plugin::Plugin {
public:
	plugin::Configuration Configure()
		{
		AddComponent(new ::analyzer::Component("SSL", ::analyzer::ssl::SSL_Analyzer::Instantiate));
		AddComponent(new ::analyzer::Component("DTLS", ::analyzer::dtls::DTLS_Analyzer::Instantiate));

		plugin::Configuration config;
		config.name = "Bro::SSL";
		config.description = "SSL/TLS and DTLS analyzers";
		return config;
		}
} plugin;

}
}

