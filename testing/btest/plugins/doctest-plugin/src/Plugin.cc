
#include "Plugin.h"

#include <zeek/3rdparty/doctest.h>

namespace btest::plugin::Demo_Doctest
	{
Plugin plugin;
	}

using namespace btest::plugin::Demo_Doctest;

zeek::plugin::Configuration Plugin::Configure()
	{
	zeek::plugin::Configuration config;
	config.name = "Demo::Doctest";
	config.description = "Run doctest in a unit-test enabled build";
	config.version.major = 1;
	config.version.minor = 0;
	config.version.patch = 0;
	return config;
	}

TEST_CASE("doctest-plugin/demotest")
	{
	CHECK(true);
	}
