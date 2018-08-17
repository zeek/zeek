
#include "Plugin.h"

#include <Func.h>
#include <Event.h>
#include <Conn.h>
#include <threading/Formatter.h>

namespace plugin { namespace Reporter_Hook { Plugin plugin; } }

using namespace plugin::Reporter_Hook;

plugin::Configuration Plugin::Configure()
	{
	EnableHook(HOOK_REPORTER);

	plugin::Configuration config;
	config.name = "Reporter::Hook";
	config.description = "Exercise Reporter Hook";
	config.version.major = 1;
	config.version.minor = 0;
	return config;
	}

bool Plugin::HookReporter(const std::string& prefix, const EventHandlerPtr event,
                          const Connection* conn, const val_list* addl, bool location,
                          const Location* location1, const Location* location2,
                          bool time, const std::string& message)
	{
	ODesc d;
	if ( location1 )
		location1->Describe(&d);
	if ( location2 )
		location2->Describe(&d);

	fprintf(stderr, " | Hook %s %s %s\n", prefix.c_str(), message.c_str(), d.Description());

	if ( message == "An Error that does not show up in the log" )
		return false;

	return true;
	}

