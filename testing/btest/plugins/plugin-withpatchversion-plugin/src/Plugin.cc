
#include "Plugin.h"

namespace btest::plugin::Testing_WithPatchVersion
	{
Plugin plugin;
	}

using namespace btest::plugin::Testing_WithPatchVersion;

zeek::plugin::Configuration Plugin::Configure()
	{
	zeek::plugin::Configuration config;
	config.name = "Testing::WithPatchVersion";
	config.description = "Testing a plugin with a specified patch version";
	config.version.major = 0;
	config.version.minor = 1;
	config.version.patch = 4;
	return config;
	}
