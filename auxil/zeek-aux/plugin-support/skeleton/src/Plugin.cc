
#include "Plugin.h"

namespace plugin { namespace @PLUGIN_NAMESPACE@_@PLUGIN_NAME@ { Plugin plugin; } }

using namespace plugin::@PLUGIN_NAMESPACE@_@PLUGIN_NAME@;

zeek::plugin::Configuration Plugin::Configure()
	{
	zeek::plugin::Configuration config;
	config.name = "@PLUGIN_NAMESPACE@::@PLUGIN_NAME@";
	config.description = "<Insert description>";
	config.version.major = 0;
	config.version.minor = 1;
	config.version.patch = 0;
	return config;
	}
