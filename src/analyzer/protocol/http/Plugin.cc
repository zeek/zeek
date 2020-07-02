// See the file  in the main distribution directory for copyright.

#include "HTTP.h"
#include "plugin/Plugin.h"
#include "analyzer/Component.h"

namespace plugin {
namespace Zeek_HTTP {

class Plugin : public zeek::plugin::Plugin {
public:
	zeek::plugin::Configuration Configure() override
		{
		AddComponent(new zeek::analyzer::Component("HTTP", ::analyzer::http::HTTP_Analyzer::Instantiate));

		zeek::plugin::Configuration config;
		config.name = "Zeek::HTTP";
		config.description = "HTTP analyzer";
		return config;
		}
} plugin;

}
}
