
#include "Plugin.h"
#include "analyzer/Component.h"

#include "Foo.h"

namespace btest::plugin::Demo_Foo { Plugin plugin; }

using namespace btest::plugin::Demo_Foo;

zeek::plugin::Configuration Plugin::Configure()
	{
	AddComponent(new zeek::analyzer::Component("Foo", btest::plugin::Demo_Foo::Foo::Instantiate, 1));

	zeek::plugin::Configuration config;
	config.name = "Demo::Foo";
	config.description = "A Foo test analyzer";
	config.version.major = 1;
	config.version.minor = 0;
	config.version.patch = 0;
	return config;
	}
