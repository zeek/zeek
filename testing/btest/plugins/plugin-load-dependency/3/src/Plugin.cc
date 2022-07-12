
#include "Plugin.h"

namespace btest::plugin::Testing_Plugin3
	{
Plugin plugin;
	}

using namespace btest::plugin::Testing_Plugin3;

extern void Plugin2_foo();

zeek::plugin::Configuration Plugin::Configure()
	{
	zeek::plugin::Configuration config;
	config.name = "Testing::Plugin3";
	config.description = "Plugin3 has a load dependency on Plugin2";
	config.version.major = 1;
	config.version.minor = 0;
	config.version.patch = 0;

	printf("in Plugin3\n");
	Plugin2_foo();

	return config;
	}
