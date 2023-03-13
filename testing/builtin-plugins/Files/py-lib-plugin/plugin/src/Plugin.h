#pragma once

#include <zeek/plugin/Plugin.h>

namespace zeek::plugin
	{
namespace Zeek_PyLib
	{

class Plugin : public zeek::plugin::Plugin
	{
protected:
	zeek::plugin::Configuration Configure() override;
	void InitPostScript() override;
	void Done() override;
	};

extern Plugin plugin;

	}
	}
