// See the file  in the main distribution directory for copyright.

#include "Ident.h"
#include "plugin/Plugin.h"
#include "analyzer/Component.h"

namespace zeek::plugin::detail::Zeek_Ident {

class Plugin : public zeek::plugin::Plugin {
public:
	zeek::plugin::Configuration Configure() override
		{
		AddComponent(new zeek::analyzer::Component("Ident", zeek::analyzer::ident::Ident_Analyzer::Instantiate));

		zeek::plugin::Configuration config;
		config.name = "Zeek::Ident";
		config.description = "Ident analyzer";
		return config;
		}
} plugin;

} // namespace zeek::plugin::detail::Zeek_Ident
