
#include "Plugin.h"

#include <Func.h>
#include <Event.h>

namespace plugin { namespace Demo_Hooks { Plugin plugin; } }

using namespace plugin::Demo_Hooks;

plugin::Configuration Plugin::Configure()
	{
	EnableHook(HOOK_LOAD_FILE);
	EnableHook(HOOK_CALL_FUNCTION);
	EnableHook(HOOK_QUEUE_EVENT);
	EnableHook(HOOK_DRAIN_EVENTS);
	EnableHook(HOOK_UPDATE_NETWORK_TIME);
	EnableHook(META_HOOK_PRE);
	EnableHook(META_HOOK_POST);
	EnableHook(HOOK_BRO_OBJ_DTOR);

	plugin::Configuration config;
	config.name = "Demo::Hooks";
	config.description = "Exercises all plugin hooks";
	config.version.major = 1;
	config.version.minor = 0;
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

int Plugin::HookLoadFile(const std::string& file, const std::string& ext)
	{
	fprintf(stderr, "%.6f %-15s %s/%s\n", network_time, "| HookLoadFile",
		file.c_str(), ext.c_str());
	return -1;
	}

std::pair<bool, Val*> Plugin::HookCallFunction(const Func* func, Frame* frame, val_list* args)
	{
	ODesc d;
	d.SetShort();
	HookArgument(func).Describe(&d);
	HookArgument(args).Describe(&d);
	fprintf(stderr, "%.6f %-15s %s\n", network_time, "| HookCallFunction",
		d.Description());

	return std::pair<bool, Val*>(false, NULL);
	}

bool Plugin::HookQueueEvent(Event* event)
	{
	ODesc d;
	d.SetShort();
	HookArgument(event).Describe(&d);
	fprintf(stderr, "%.6f %-15s %s\n", network_time, "| HookQueueEvent",
		d.Description());

	static int i = 0;

	if ( network_time && i == 0 )
		{
		fprintf(stderr, "%.6f %-15s %s\n", network_time, "| RequestObjDtor",
			d.Description());

		RequestBroObjDtor(event);
		i = 1;
		}

	return false;
	}

void Plugin::HookDrainEvents()
	{
	fprintf(stderr, "%.6f %-15s\n", network_time, "| HookDrainEvents");
	}

void Plugin::HookUpdateNetworkTime(double network_time)
	{
	fprintf(stderr, "%.6f  %-15s %.6f\n", ::network_time, "| HookUpdateNetworkTime",
		network_time);
	}

void Plugin::HookBroObjDtor(void* obj)
	{
	fprintf(stderr, "%.6f  %-15s\n", ::network_time, "| HookBroObjDtor");
	}

void Plugin::MetaHookPre(HookType hook, const HookArgumentList& args)
	{
	ODesc d;
	d.SetShort();
	describe_hook_args(args, &d);
	fprintf(stderr, "%.6f %-15s %s(%s)\n", network_time, "  MetaHookPre",
		hook_name(hook), d.Description());
	}

void Plugin::MetaHookPost(HookType hook, const HookArgumentList& args, HookArgument result)
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
