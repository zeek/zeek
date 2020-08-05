// See the file  in the main distribution directory for copyright.

#include "SSL.h"
#include "DTLS.h"
#include "plugin/Plugin.h"
#include "analyzer/Component.h"

namespace plugin {
namespace Zeek_SSL {

class Plugin : public zeek::plugin::Plugin {
public:
	zeek::plugin::Configuration Configure() override
		{
		AddComponent(new zeek::analyzer::Component("SSL", ::analyzer::ssl::SSL_Analyzer::Instantiate));
		AddComponent(new zeek::analyzer::Component("DTLS", ::analyzer::dtls::DTLS_Analyzer::Instantiate));

		zeek::plugin::Configuration config;
		config.name = "Zeek::SSL";
		config.description = "SSL/TLS and DTLS analyzers";
		return config;
		}
} plugin;

}
}
