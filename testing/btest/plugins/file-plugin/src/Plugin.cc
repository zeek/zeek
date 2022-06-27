
#include "Plugin.h"

#include "Foo.h"
#include "file_analysis/Component.h"
#include "file_analysis/File.h"

namespace btest::plugin::Demo_Foo
	{
Plugin plugin;
	}

using namespace btest::plugin::Demo_Foo;

zeek::plugin::Configuration Plugin::Configure()
	{
	AddComponent(
		new zeek::file_analysis::Component("Foo", btest::plugin::Demo_Foo::Foo::Instantiate));

	zeek::plugin::Configuration config;
	config.name = "Demo::Foo";
	config.description = "A Foo test analyzer";
	config.version.major = 1;
	config.version.minor = 0;
	config.version.patch = 0;
	return config;
	}
