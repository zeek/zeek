#pragma once

#include <string>

#include "zeek/plugin/Plugin.h"

namespace btest::plugin::Demo_PublishEvent {

class Plugin : public zeek::plugin::Plugin {
protected:
    zeek::plugin::Configuration Configure() override;
    void InitPostScript() override;

    bool HookPublishEvent(zeek::cluster::Backend& backend, const std::string& topic,
                          zeek::cluster::Event& event) override;

    void MetaHookPre(zeek::plugin::HookType hook, const zeek::plugin::HookArgumentList& args) override;
    void MetaHookPost(zeek::plugin::HookType hook, const zeek::plugin::HookArgumentList& args,
                      zeek::plugin::HookArgument result) override;
};

extern Plugin plugin;

} // namespace btest::plugin::Demo_PublishEvent
