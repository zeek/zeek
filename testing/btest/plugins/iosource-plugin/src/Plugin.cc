
#include "Plugin.h"

namespace zeek::run_state
	{
extern double processing_start_time;
	}

namespace btest::plugin::Demo_Iosource
	{
Plugin plugin;
	}

using namespace btest::plugin::Demo_Iosource;

zeek::plugin::Configuration Plugin::Configure()
	{
	EnableHook(zeek::plugin::HOOK_DRAIN_EVENTS, 0);

	zeek::plugin::Configuration config;
	config.name = "Demo::Iosource";
	config.description = "This is a iosource";
	config.version.major = 1;
	config.version.minor = 0;
	config.version.patch = 0;
	return config;
	}

void Plugin::InitPostScript()
	{
	std::fprintf(stdout, "%.6f InitPostScript\n", zeek::run_state::network_time);
	ts1 = new TimeoutSource("timeout-source-1");
	ts2 = new TimeoutSource("timeout-source-2");
	fd1 = new FdSource("fd-source-1");
	fd2 = new FdSource("fd-source-2");
	}

void Plugin::HookDrainEvents()
	{
	++round;
	if ( zeek::run_state::processing_start_time != 0.0 ) // ignore drains from dispatch_packet
		return;
	//
	std::fprintf(stdout, "%.6f HookDrainEvents %d\n", zeek::run_state::network_time, round);

	if ( (round % 9) == 0 )
		{
		std::fprintf(stdout, "%.6f   Firing %s\n", zeek::run_state::network_time, ts1->Tag());
		ts1->Fire();
		}

	if ( (round % 19) == 0 )
		{
		std::fprintf(stdout, "%.6f   Firing %s\n", zeek::run_state::network_time, ts2->Tag());
		ts2->Fire();
		}

	if ( (round % 19) == 0 )
		{
		std::fprintf(stdout, "%.6f   Firing %s\n", zeek::run_state::network_time, fd1->Tag());
		fd1->Fire();
		}

	if ( (round % 23) == 0 )
		{
		std::fprintf(stdout, "%.6f   Firing %s\n", zeek::run_state::network_time, fd2->Tag());
		fd2->Fire();
		}
	}
