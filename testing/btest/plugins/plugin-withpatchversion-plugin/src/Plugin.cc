
#include "Plugin.h"

namespace plugin { namespace Testing_WithPatchVersion { Plugin plugin; } }

using namespace plugin::Testing_WithPatchVersion;

plugin::Configuration Plugin::Configure()
	{
	plugin::Configuration config;
	config.name = "Testing::WithPatchVersion";
	config.description = "Testing a plugin with a specified patch version";
	config.version.major = 0;
	config.version.minor = 1;
	config.version.patch = 4;
	return config;
	}
