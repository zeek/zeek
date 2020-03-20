#include "plugin/Plugin.h"
#include "analyzer/Component.h"

#include "FOO.h"

namespace plugin {
namespace Foo_FOO {

class Plugin : public plugin::Plugin {
public:
	plugin::Configuration Configure()
		{
		AddComponent(new ::analyzer::Component("FOO",
		             ::analyzer::FOO::FOO_Analyzer::InstantiateAnalyzer));

		plugin::Configuration config;
		config.name = "FOO::Foo";
		config.description = "Foo Analyzer analyzer";
		config.version.major = 1;
		config.version.minor = 0;
		return config;
		}
} plugin;

}
}
