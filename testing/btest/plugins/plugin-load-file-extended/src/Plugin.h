
#pragma once

#include <zeek/plugin/Plugin.h>

namespace btest::plugin::Testing_LoadFileExtended
	{

class Plugin : public zeek::plugin::Plugin
	{
protected:
	// Overridden from zeek::plugin::Plugin.
	zeek::plugin::Configuration Configure() override;
	std::pair<int, std::optional<std::string>>
	HookLoadFileExtended(const Plugin::LoadType type, const std::string& file,
	                     const std::string& resolved) override;
	};

extern Plugin plugin;

	}
