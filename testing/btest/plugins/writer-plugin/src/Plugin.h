
#pragma once

#include <plugin/Plugin.h>

namespace btest::plugin::Demo_Foo
	{

class Plugin : public zeek::plugin::Plugin
	{
protected:
	// Overridden from plugin::Plugin.
	virtual zeek::plugin::Configuration Configure();
	};

extern Plugin plugin;

	}
