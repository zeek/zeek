// See the file  in the main distribution directory for copyright.

#include "Gnutella.h"
#include "plugin/Plugin.h"
#include "analyzer/Component.h"

namespace plugin {
namespace Zeek_Gnutella {

class Plugin : public plugin::Plugin {
public:
	plugin::Configuration Configure() override
		{
		AddComponent(new ::analyzer::Component("Gnutella", ::analyzer::gnutella::Gnutella_Analyzer::Instantiate));

		plugin::Configuration config;
		config.name = "Zeek::Gnutella";
		config.description = "Gnutella analyzer";
		return config;
		}
} plugin;

}
}
