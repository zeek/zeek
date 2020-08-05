// See the file  in the main distribution directory for copyright.

#include "SOCKS.h"
#include "plugin/Plugin.h"
#include "analyzer/Component.h"

namespace plugin {
namespace Zeek_SOCKS {

class Plugin : public zeek::plugin::Plugin {
public:
	zeek::plugin::Configuration Configure() override
		{
		AddComponent(new zeek::analyzer::Component("SOCKS", ::analyzer::socks::SOCKS_Analyzer::Instantiate));

		zeek::plugin::Configuration config;
		config.name = "Zeek::SOCKS";
		config.description = "SOCKS analyzer";
		return config;
		}
} plugin;

}
}
