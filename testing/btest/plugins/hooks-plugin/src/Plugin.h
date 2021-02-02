
#pragma once

#include <plugin/Plugin.h>

namespace btest::plugin::Demo_Hooks {

class Plugin : public zeek::plugin::Plugin
{
protected:
	int HookLoadFile(const LoadType type, const std::string& file, const std::string& resolved) override;
	std::pair<bool, zeek::ValPtr> HookFunctionCall(const zeek::Func* func, zeek::detail::Frame* parent,
	                                               zeek::Args* args) override;
	bool HookQueueEvent(zeek::Event* event) override;
	void HookDrainEvents() override;
	void HookUpdateNetworkTime(double network_time) override;
	void HookBroObjDtor(void* obj) override;
	void HookLogInit(const std::string& writer, const std::string& instantiating_filter, bool local, bool remote,
	                 const zeek::logging::WriterBackend::WriterInfo& info, int num_fields,
	                 const zeek::threading::Field* const* fields) override;
	bool HookLogWrite(const std::string& writer, const std::string& filter,
	                  const zeek::logging::WriterBackend::WriterInfo& info,
	                  int num_fields, const zeek::threading::Field* const* fields,
	                  zeek::threading::Value** vals) override;
	void HookSetupAnalyzerTree(zeek::Connection *conn) override;
	void MetaHookPre(zeek::plugin::HookType hook, const zeek::plugin::HookArgumentList& args) override;
	void MetaHookPost(zeek::plugin::HookType hook, const zeek::plugin::HookArgumentList& args,
	                  zeek::plugin::HookArgument result) override;

	void RenderVal(const zeek::threading::Value* val, zeek::ODesc &d) const;

	// Overridden from zeek::plugin::Plugin.
	zeek::plugin::Configuration Configure() override;
};

extern Plugin plugin;

}
