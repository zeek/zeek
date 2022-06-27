
#include "Plugin.h"

namespace btest::plugin::Testing_Plugin2
	{
Plugin plugin;
	}

using namespace btest::plugin::Testing_Plugin2;

void Plugin2_foo()
	{
	printf("in Plugin2\n");
	}

zeek::plugin::Configuration Plugin::Configure()
	{
	zeek::plugin::Configuration config;
	config.name = "Testing::Plugin2";
	config.description = "Plugin2 provides a load dependency for Plugin1 and Plugin3";
	config.version.major = 1;
	config.version.minor = 0;
	config.version.patch = 0;
	return config;
	}
