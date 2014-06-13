
#include <plugin/Plugin.h>

#include <Func.h>
#include <Event.h>

namespace plugin {
namespace Demo_Hooks {

class Plugin : public plugin::Plugin
{
protected:
	plugin::Configuration Configure()
		{
		EnableHook(HOOK_LOAD_FILE);
		EnableHook(HOOK_CALL_FUNCTION);
		EnableHook(HOOK_QUEUE_EVENT);
		EnableHook(HOOK_DRAIN_EVENTS);
		EnableHook(HOOK_UPDATE_NETWORK_TIME);
		EnableHook(META_HOOK_PRE);
		EnableHook(META_HOOK_POST);

		plugin::Configuration config;
		config.name = "Demo::Hooks";
		config.description = "Exercises all plugin hooks";
		config.version.major = 1;
		config.version.minor = 0;
		return config;
		}

	virtual int HookLoadFile(const std::string& file, const std::string& ext);
	virtual Val* HookCallFunction(const Func* func, val_list* args);
	virtual bool HookQueueEvent(Event* event);
	virtual void HookDrainEvents();
	virtual void HookUpdateNetworkTime(double network_time);
	virtual void MetaHookPre(HookType hook, const HookArgumentList& args);
	virtual void MetaHookPost(HookType hook, const HookArgumentList& args, HookArgument result);

} plugin;

static void describe_hook_args(const HookArgumentList& args, ODesc* d)
	{
	bool first = true;

	for ( HookArgumentList::const_iterator i = args.begin(); i != args.end(); i++ )
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

Val* Plugin::HookCallFunction(const Func* func, val_list* args)
	{
	ODesc d;
	d.SetShort();
	HookArgument(func).Describe(&d);
	HookArgument(args).Describe(&d);
	fprintf(stderr, "%.6f %-15s %s\n", network_time, "| HookCallFunction",
		d.Description());
	return 0;
	}

bool Plugin::HookQueueEvent(Event* event)
	{
	ODesc d;
	d.SetShort();
	HookArgument(event).Describe(&d);
	fprintf(stderr, "%.6f %-15s %s\n", network_time, "| HookQueueEvent",
		d.Description());
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

}
}
