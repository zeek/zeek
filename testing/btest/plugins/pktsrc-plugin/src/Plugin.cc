
#include "Plugin.h"

#include "Foo.h"
#include "iosource/Component.h"

namespace btest::plugin::Demo_Foo
	{
Plugin plugin;
	}

using namespace btest::plugin::Demo_Foo;

zeek::plugin::Configuration Plugin::Configure()
	{
	AddComponent(new zeek::iosource::PktSrcComponent("FooPktSrc", "foo",
	                                                 zeek::iosource::PktSrcComponent::BOTH,
	                                                 btest::plugin::Demo_Foo::Foo::Instantiate));

	zeek::plugin::Configuration config;
	config.name = "Demo::Foo";
	config.description = "A Foo packet source";
	config.version.major = 1;
	config.version.minor = 0;
	config.version.patch = 0;
	return config;
	}
