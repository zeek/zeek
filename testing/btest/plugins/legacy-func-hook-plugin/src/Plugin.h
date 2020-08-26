
#pragma once

#include <plugin/Plugin.h>

namespace btest::plugin::Demo_Hooks {

class Plugin : public zeek::plugin::Plugin
{
protected:
	std::pair<bool, zeek::Val*> HookCallFunction(const zeek::Func* func, zeek::detail::Frame* frame, zeek::ValPList* args) override;

	/* std::pair<bool, IntrusivePtr<Val>> HookFunctionCall(const Func* func, */
	/*                                                     Frame* frame, */
	/*                                                     zeek::Args* args) override; */

	void MetaHookPre(zeek::plugin::HookType hook,
	                 const zeek::plugin::HookArgumentList& args) override;
	void MetaHookPost(zeek::plugin::HookType hook,
	                  const zeek::plugin::HookArgumentList& args,
	                  zeek::plugin::HookArgument result) override;

	// Overridden from plugin::Plugin.
	zeek::plugin::Configuration Configure() override;
};

extern Plugin plugin;

}
