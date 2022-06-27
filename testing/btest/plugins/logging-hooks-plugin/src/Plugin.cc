
#include "Plugin.h"

#include <Conn.h>
#include <Desc.h>
#include <Event.h>
#include <Func.h>
#include <RunState.h>
#include <threading/Formatter.h>

namespace btest::plugin::Log_Hooks
	{
Plugin plugin;
	}

using namespace btest::plugin::Log_Hooks;

zeek::plugin::Configuration Plugin::Configure()
	{
	round = 0;
	EnableHook(zeek::plugin::HOOK_LOG_INIT);
	EnableHook(zeek::plugin::HOOK_LOG_WRITE);

	zeek::plugin::Configuration config;
	config.name = "Log::Hooks";
	config.description = "Exercises Log hooks";
	config.version.major = 1;
	config.version.minor = 0;
	config.version.patch = 0;
	return config;
	}

void Plugin::HookLogInit(const std::string& writer, const std::string& instantiating_filter,
                         bool local, bool remote,
                         const zeek::logging::WriterBackend::WriterInfo& info, int num_fields,
                         const zeek::threading::Field* const* fields)
	{
	zeek::ODesc d;

	d.Add("{");
	for ( int i = 0; i < num_fields; i++ )
		{
		const zeek::threading::Field* f = fields[i];

		if ( i > 0 )
			d.Add(", ");

		d.Add(f->name);
		d.Add(" (");
		d.Add(f->TypeName());
		d.Add(")");
		}
	d.Add("}");

	fprintf(stderr, "%.6f %-15s %s %d/%d %s\n", zeek::run_state::network_time, "| HookLogInit",
	        info.path, local, remote, d.Description());
	}

bool Plugin::HookLogWrite(const std::string& writer, const std::string& filter,
                          const zeek::logging::WriterBackend::WriterInfo& info, int num_fields,
                          const zeek::threading::Field* const* fields,
                          zeek::threading::Value** vals)
	{
	round++;
	if ( round == 1 ) // do not output line
		return false;
	else if ( round == 2 )
		vals[0]->val.int_val = 0;
	else if ( round == 3 )
		vals[1]->present = false;

	return true;
	}
