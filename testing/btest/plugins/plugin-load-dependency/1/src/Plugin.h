
#pragma once

#include <zeek/plugin/Plugin.h>

namespace btest::plugin::Testing_Plugin1
	{

class Plugin : public zeek::plugin::Plugin
	{
protected:
	// Overridden from zeek::plugin::Plugin.
	zeek::plugin::Configuration Configure() override;
	};

extern Plugin plugin;

	}
