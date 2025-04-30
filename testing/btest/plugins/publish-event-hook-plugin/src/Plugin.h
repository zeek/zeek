#pragma once

#include <zeek/plugin/Plugin.h>
#include <string>

namespace btest::plugin::Demo_PublishEvent {

class Plugin : public zeek::plugin::Plugin {
protected:
    zeek::plugin::Configuration Configure() override;
    void InitPostScript() override;

    bool HookPublishEvent(zeek::cluster::Backend& backend, const std::string& topic,
                          zeek::cluster::detail::Event& event) override;

    void MetaHookPre(zeek::plugin::HookType hook, const zeek::plugin::HookArgumentList& args) override;
    void MetaHookPost(zeek::plugin::HookType hook, const zeek::plugin::HookArgumentList& args,
                      zeek::plugin::HookArgument result) override;
};

extern Plugin plugin;

} // namespace btest::plugin::Demo_PublishEvent
