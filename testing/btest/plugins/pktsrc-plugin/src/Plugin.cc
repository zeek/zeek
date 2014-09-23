
#include "Plugin.h"

#include "Foo.h"

namespace plugin { namespace Demo_Foo { Plugin plugin; } }

using namespace plugin::Demo_Foo;

plugin::Configuration Plugin::Configure()
	{
	AddComponent(new ::iosource::PktSrcComponent("FooPktSrc", "foo", ::iosource::PktSrcComponent::BOTH, ::plugin::Demo_Foo::Foo::Instantiate));

	plugin::Configuration config;
	config.name = "Demo::Foo";
	config.description = "A Foo packet source";
	config.version.major = 1;
	config.version.minor = 0;
	return config;
	}
