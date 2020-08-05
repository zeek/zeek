// See the file  in the main distribution directory for copyright.

#include "IRC.h"
#include "plugin/Plugin.h"
#include "analyzer/Component.h"

namespace plugin {
namespace Zeek_IRC {

class Plugin : public zeek::plugin::Plugin {
public:
	zeek::plugin::Configuration Configure() override
		{
		AddComponent(new zeek::analyzer::Component("IRC", ::analyzer::irc::IRC_Analyzer::Instantiate));

		zeek::plugin::Configuration config;
		config.name = "Zeek::IRC";
		config.description = "IRC analyzer";
		return config;
		}
} plugin;

}
}
