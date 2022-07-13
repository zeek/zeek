
#pragma once

#include <plugin/Plugin.h>

namespace btest::plugin::Reporter_Hook
	{

class Plugin : public zeek::plugin::Plugin
	{
protected:
	bool HookReporter(const std::string& prefix, const zeek::EventHandlerPtr event,
	                  const zeek::Connection* conn, const zeek::ValPList* addl, bool location,
	                  const zeek::detail::Location* location1,
	                  const zeek::detail::Location* location2, bool time,
	                  const std::string& buffer) override;

	// Overridden from plugin::Plugin.
	zeek::plugin::Configuration Configure() override;
	};

extern Plugin plugin;

	}
