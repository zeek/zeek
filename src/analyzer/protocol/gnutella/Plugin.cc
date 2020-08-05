// See the file  in the main distribution directory for copyright.

#include "Gnutella.h"
#include "plugin/Plugin.h"
#include "analyzer/Component.h"

namespace plugin {
namespace Zeek_Gnutella {

class Plugin : public zeek::plugin::Plugin {
public:
	zeek::plugin::Configuration Configure() override
		{
		AddComponent(new zeek::analyzer::Component("Gnutella", ::analyzer::gnutella::Gnutella_Analyzer::Instantiate));

		zeek::plugin::Configuration config;
		config.name = "Zeek::Gnutella";
		config.description = "Gnutella analyzer";
		return config;
		}
} plugin;

}
}
