#include "Plugin.h"

#include "Foo.h"

namespace btest::plugin::Demo_Foo
	{
Plugin plugin;
	}

using namespace btest::plugin::Demo_Foo;

zeek::plugin::Configuration Plugin::Configure()
	{
	AddComponent(new zeek::input::Component("Foo", btest::input::reader::Foo::Instantiate));

	zeek::plugin::Configuration config;
	config.name = "Demo::Foo";
	config.description = "A Foo test input reader";
	config.version.major = 1;
	config.version.minor = 0;
	config.version.patch = 0;
	return config;
	}
