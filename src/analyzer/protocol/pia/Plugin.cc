// See the file  in the main distribution directory for copyright.

#include "PIA.h"
#include "plugin/Plugin.h"
#include "analyzer/Component.h"

namespace plugin {
namespace Zeek_PIA {

class Plugin : public zeek::plugin::Plugin {
public:
	zeek::plugin::Configuration Configure() override
		{
		AddComponent(new zeek::analyzer::Component("PIA_TCP", ::analyzer::pia::PIA_TCP::Instantiate));
		AddComponent(new zeek::analyzer::Component("PIA_UDP", ::analyzer::pia::PIA_UDP::Instantiate));

		zeek::plugin::Configuration config;
		config.name = "Zeek::PIA";
		config.description = "Analyzers implementing Dynamic Protocol";
		return config;
		}
} plugin;

}
}
