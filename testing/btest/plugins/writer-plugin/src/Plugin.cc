#include "Plugin.h"

#include "Foo.h"

namespace plugin { namespace Demo_Foo { Plugin plugin; } }

using namespace plugin::Demo_Foo;

plugin::Configuration Plugin::Configure()
	{
	AddComponent(new ::logging::Component("Foo", ::logging::writer::Foo::Instantiate));

	plugin::Configuration config;
	config.name = "Demo::Foo";
	config.description = "A Foo test logging writer";
	config.version.major = 1;
	config.version.minor = 0;
	return config;
	}
