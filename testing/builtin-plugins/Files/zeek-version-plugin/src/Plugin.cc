
#include "Plugin.h"

#include <zeek/Reporter.h>
#include <zeek/zeek-config.h>

namespace btest::plugin::Demo_Version
	{
Plugin plugin;
	}

using namespace btest::plugin::Demo_Version;

zeek::plugin::Configuration Plugin::Configure()
	{
	zeek::plugin::Configuration config;
	config.name = "Demo::Version";
	config.description = "Tries to use ZEEK_VERSION_NUMBER";
	config.version.major = 1;
	config.version.minor = 0;
	config.version.patch = 0;
	return config;
	}

void Plugin::InitPostScript()
	{
#ifndef ZEEK_VERSION_NUMBER
#error "ZEEK_VERSION_NUMBER is not defined"
#endif
	zeek::reporter->Info("All good ZEEK_VERSION_NUMBER=%d\n", ZEEK_VERSION_NUMBER);
	}
