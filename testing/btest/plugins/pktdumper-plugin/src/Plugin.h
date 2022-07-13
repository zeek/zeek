
#pragma once

#include <zeek/plugin/Plugin.h>

namespace btest::plugin::Demo_Foo
	{

class Plugin : public zeek::plugin::Plugin
	{
protected:
	// Overridden from zeek::plugin::Plugin.
	zeek::plugin::Configuration Configure() override;
	};

extern Plugin plugin;

	}
