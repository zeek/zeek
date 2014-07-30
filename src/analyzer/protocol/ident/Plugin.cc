// See the file  in the main distribution directory for copyright.


#include "plugin/Plugin.h"

#include "Ident.h"

namespace plugin {
namespace Bro_Ident {

class Plugin : public plugin::Plugin {
public:
	plugin::Configuration Configure()
		{
		AddComponent(new ::analyzer::Component("Ident", ::analyzer::ident::Ident_Analyzer::Instantiate));

		plugin::Configuration config;
		config.name = "Bro::Ident";
		config.description = "Ident analyzer";
		return config;
		}
} plugin;

}
}
