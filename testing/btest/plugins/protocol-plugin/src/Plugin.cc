
#include <plugin/Plugin.h>

#include "Foo.h"

namespace plugin {
namespace Demo_Foo {

class Plugin : public plugin::Plugin {
public:
	plugin::Configuration Configure()
		{
		AddComponent(new ::analyzer::Component("Foo", plugin::Demo_Foo::Foo::Instantiate));

		plugin::Configuration config;
		config.name = "Demo::Foo";
		config.description = "A Foo test analyzer";
		config.version.major = 1;
		config.version.minor = 0;
		return config;
		}
} plugin;

}
}
