
#pragma once

#include <zeek/plugin/Plugin.h>

namespace btest::plugin::Demo_Meta_Hooks {

class Plugin : public zeek::plugin::Plugin {
protected:
    bool HookQueueEvent(zeek::Event* e) override;
    void MetaHookPre(zeek::plugin::HookType hook, const zeek::plugin::HookArgumentList& args) override;
    void MetaHookPost(zeek::plugin::HookType hook, const zeek::plugin::HookArgumentList& args,
                      zeek::plugin::HookArgument result) override;

    // Overridden from plugin::Plugin.
    zeek::plugin::Configuration Configure() override;
};

extern Plugin plugin;

} // namespace btest::plugin::Demo_Meta_Hooks
