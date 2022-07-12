
#include "Plugin.h"

namespace btest::plugin::Testing_NoPatchVersion
	{
Plugin plugin;
	}

using namespace btest::plugin::Testing_NoPatchVersion;

zeek::plugin::Configuration Plugin::Configure()
	{
	zeek::plugin::Configuration config;
	config.name = "Testing::NoPatchVersion";
	config.description = "Testing a plugin without a specified patch version";
	config.version.major = 0;
	config.version.minor = 1;
	return config;
	}
