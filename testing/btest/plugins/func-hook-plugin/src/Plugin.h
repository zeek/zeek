
#pragma once

#include <plugin/Plugin.h>

namespace plugin {
namespace Demo_Hooks {

class Plugin : public ::plugin::Plugin
{
protected:

	std::pair<bool, IntrusivePtr<Val>> HookFunctionCall(const Func* func,
	                                                    Frame* frame,
	                                                    zeek::Args* args) override;

	void MetaHookPre(HookType hook, const HookArgumentList& args) override;
	void MetaHookPost(HookType hook, const HookArgumentList& args, HookArgument result) override;

	// Overridden from plugin::Plugin.
	plugin::Configuration Configure() override;
};

extern Plugin plugin;

}
}
