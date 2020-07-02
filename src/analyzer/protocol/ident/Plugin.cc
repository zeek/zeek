// See the file  in the main distribution directory for copyright.

#include "Ident.h"
#include "plugin/Plugin.h"
#include "analyzer/Component.h"

namespace plugin {
namespace Zeek_Ident {

class Plugin : public zeek::plugin::Plugin {
public:
	zeek::plugin::Configuration Configure() override
		{
		AddComponent(new zeek::analyzer::Component("Ident", ::analyzer::ident::Ident_Analyzer::Instantiate));

		zeek::plugin::Configuration config;
		config.name = "Zeek::Ident";
		config.description = "Ident analyzer";
		return config;
		}
} plugin;

}
}
