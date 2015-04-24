
#ifndef BRO_PLUGIN_Demo_Hooks
#define BRO_PLUGIN_Demo_Hooks

#include <plugin/Plugin.h>

namespace plugin {
namespace Demo_Hooks {

class Plugin : public ::plugin::Plugin
{
protected:
	virtual int HookLoadFile(const std::string& file, const std::string& ext);
	virtual std::pair<bool, Val*> HookCallFunction(const Func* func, Frame* frame, val_list* args);
	virtual bool HookQueueEvent(Event* event);
	virtual void HookDrainEvents();
	virtual void HookUpdateNetworkTime(double network_time);
	virtual void HookBroObjDtor(void* obj);
	virtual void MetaHookPre(HookType hook, const HookArgumentList& args);
	virtual void MetaHookPost(HookType hook, const HookArgumentList& args, HookArgument result);

	// Overridden from plugin::Plugin.
	virtual plugin::Configuration Configure();
};

extern Plugin plugin;

}
}

#endif
