
#include "Foo.h"
#include "Plugin.h"
#include "file_analysis/Component.h"
#include "file_analysis/File.h"

namespace plugin { namespace Demo_Foo { Plugin plugin; } }

using namespace plugin::Demo_Foo;

plugin::Configuration Plugin::Configure()
	{
	AddComponent(new ::file_analysis::Component("Foo", ::plugin::Demo_Foo::Foo::Instantiate));

	plugin::Configuration config;
	config.name = "Demo::Foo";
	config.description = "A Foo test analyzer";
	config.version.major = 1;
	config.version.minor = 0;
	config.version.patch = 0;
	return config;
	}
