
#include "Plugin.h"

namespace plugin { namespace Testing_NoPatchVersion { Plugin plugin; } }

using namespace plugin::Testing_NoPatchVersion;

plugin::Configuration Plugin::Configure()
	{
	plugin::Configuration config;
	config.name = "Testing::NoPatchVersion";
	config.description = "Testing a plugin without a specified patch version";
	config.version.major = 0;
	config.version.minor = 1;
	return config;
	}
