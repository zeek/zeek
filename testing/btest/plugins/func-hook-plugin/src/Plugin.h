
#pragma once

#include <zeek/plugin/Plugin.h>

namespace btest::plugin::Demo_Hooks
	{

class Plugin : public zeek::plugin::Plugin
	{
protected:
	std::pair<bool, zeek::ValPtr>
	HookFunctionCall(const zeek::Func* func, zeek::detail::Frame* frame, zeek::Args* args) override;

	void MetaHookPre(zeek::plugin::HookType hook,
	                 const zeek::plugin::HookArgumentList& args) override;
	void MetaHookPost(zeek::plugin::HookType hook, const zeek::plugin::HookArgumentList& args,
	                  zeek::plugin::HookArgument result) override;

	// Overridden from plugin::Plugin.
	zeek::plugin::Configuration Configure() override;
	};

extern Plugin plugin;

	}
