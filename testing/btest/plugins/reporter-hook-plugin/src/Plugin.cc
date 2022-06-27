
#include "Plugin.h"

#include <Conn.h>
#include <Desc.h>
#include <Event.h>
#include <Func.h>
#include <threading/Formatter.h>

namespace btest::plugin::Reporter_Hook
	{
Plugin plugin;
	}

using namespace btest::plugin::Reporter_Hook;

zeek::plugin::Configuration Plugin::Configure()
	{
	EnableHook(zeek::plugin::HOOK_REPORTER);

	zeek::plugin::Configuration config;
	config.name = "Reporter::Hook";
	config.description = "Exercise Reporter Hook";
	config.version.major = 1;
	config.version.minor = 0;
	config.version.patch = 0;
	return config;
	}

bool Plugin::HookReporter(const std::string& prefix, const zeek::EventHandlerPtr event,
                          const zeek::Connection* conn, const zeek::ValPList* addl, bool location,
                          const zeek::detail::Location* location1,
                          const zeek::detail::Location* location2, bool time,
                          const std::string& message)
	{
	zeek::ODesc d;
	if ( location1 )
		location1->Describe(&d);
	if ( location2 )
		location2->Describe(&d);

	fprintf(stderr, " | Hook %s %s %s\n", prefix.c_str(), message.c_str(), d.Description());

	if ( message == "An Error that does not show up in the log" )
		return false;

	return true;
	}
