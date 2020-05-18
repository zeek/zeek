// See the file  in the main distribution directory for copyright.

#include "XMPP.h"
#include "plugin/Plugin.h"
#include "analyzer/Component.h"

namespace plugin {
namespace Zeek_XMPP {

class Plugin : public plugin::Plugin {
public:
	plugin::Configuration Configure() override
		{
		AddComponent(new ::analyzer::Component("XMPP", ::analyzer::xmpp::XMPP_Analyzer::Instantiate));

		plugin::Configuration config;
		config.name = "Zeek::XMPP";
		config.description = "XMPP analyzer (StartTLS only)";
		return config;
		}
} plugin;

}
}
