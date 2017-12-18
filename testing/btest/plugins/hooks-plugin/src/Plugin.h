
#ifndef BRO_PLUGIN_Demo_Hooks
#define BRO_PLUGIN_Demo_Hooks

#include <plugin/Plugin.h>

namespace plugin {
namespace Demo_Hooks {

class Plugin : public ::plugin::Plugin
{
protected:
	int HookLoadFile(const LoadType type, const std::string& file, const std::string& resolved) override;
	std::pair<bool, Val*> HookCallFunction(const Func* func, Frame* frame, val_list* args) override;
	bool HookQueueEvent(Event* event) override;
	void HookDrainEvents() override;
	void HookUpdateNetworkTime(double network_time) override;
	void HookBroObjDtor(void* obj) override;
	void HookLogInit(const std::string& writer, const std::string& instantiating_filter, bool local, bool remote, const logging::WriterBackend::WriterInfo& info, int num_fields, const threading::Field* const* fields) override;
	bool HookLogWrite(const std::string& writer, const std::string& filter, const logging::WriterBackend::WriterInfo& info, int num_fields, const threading::Field* const* fields, threading::Value** vals) override;
	void HookSetupAnalyzerTree(Connection *conn) override;
	void MetaHookPre(HookType hook, const HookArgumentList& args) override;
	void MetaHookPost(HookType hook, const HookArgumentList& args, HookArgument result) override;

	void RenderVal(const threading::Value* val, ODesc &d) const;

	// Overridden from plugin::Plugin.
	plugin::Configuration Configure() override;
};

extern Plugin plugin;

}
}

#endif
