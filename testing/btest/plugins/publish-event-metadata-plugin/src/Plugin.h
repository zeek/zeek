#pragma once

#include <zeek/plugin/Plugin.h>
#include <string>

namespace btest::plugin::Demo_PublishEventMetadata {

class Plugin : public zeek::plugin::Plugin {
protected:
    zeek::plugin::Configuration Configure() override;
    void InitPostScript() override;

    bool HookPublishEvent(zeek::cluster::Backend& backend, const std::string& topic,
                          zeek::cluster::Event& event) override;
};

extern Plugin plugin;

} // namespace btest::plugin::Demo_PublishEventMetadata
