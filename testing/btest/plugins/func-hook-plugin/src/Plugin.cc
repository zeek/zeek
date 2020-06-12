
#include "Plugin.h"

#include <Val.h>
#include <Func.h>
#include <Event.h>
#include <Conn.h>
#include <Desc.h>
#include <threading/Formatter.h>

namespace plugin { namespace Demo_Hooks { Plugin plugin; } }

using namespace plugin::Demo_Hooks;

plugin::Configuration Plugin::Configure()
	{
	EnableHook(HOOK_CALL_FUNCTION);
	EnableHook(META_HOOK_PRE);
	EnableHook(META_HOOK_POST);

	plugin::Configuration config;
	config.name = "Demo::Hooks";
	config.description = "Exercises all plugin hooks";
	config.version.major = 1;
	config.version.minor = 0;
	config.version.patch = 0;
	return config;
	}

static void describe_hook_args(const plugin::HookArgumentList& args, ODesc* d)
	{
	bool first = true;

	for ( plugin::HookArgumentList::const_iterator i = args.begin(); i != args.end(); i++ )
		{
		if ( ! first )
			d->Add(", ");

		i->Describe(d);
		first = false;
		}
	}

std::pair<bool, IntrusivePtr<Val>> Plugin::HookFunctionCall(const Func* func,
                                                            Frame* frame,
                                                            zeek::Args* args)
	{
	ODesc d;
	d.SetShort();
	HookArgument(func).Describe(&d);
	HookArgument(args).Describe(&d);
	fprintf(stderr, "%.6f %-15s %s\n", network_time, "| HookFunctionCall",
		d.Description());

	if ( streq(func->Name(), "foo") )
		{
		auto& vl = *args;
		vl[0] = val_mgr->Count(42);
		}

	return {};
	}

void Plugin::MetaHookPre(zeek::plugin::HookType hook, const zeek::plugin::HookArgumentList& args)
	{
	ODesc d;
	d.SetShort();
	describe_hook_args(args, &d);
	fprintf(stderr, "%.6f %-15s %s(%s)\n", network_time, "  MetaHookPre",
		hook_name(hook), d.Description());
	}

void Plugin::MetaHookPost(zeek::plugin::HookType hook,
	                      const zeek::plugin::HookArgumentList& args,
                          zeek::plugin::HookArgument result)
	{
	ODesc d1;
	d1.SetShort();
	describe_hook_args(args, &d1);

	ODesc d2;
	d2.SetShort();
	result.Describe(&d2);

	fprintf(stderr, "%.6f %-15s %s(%s) -> %s\n", network_time, "  MetaHookPost",
		hook_name(hook), d1.Description(),
		d2.Description());
	}
