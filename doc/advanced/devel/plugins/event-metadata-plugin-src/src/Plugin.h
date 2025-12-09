
#pragma once

#include <zeek/plugin/Plugin.h>
#include <zeek/telemetry/Histogram.h>

namespace plugin {
namespace Zeek_EventLatency {

class Plugin : public zeek::plugin::Plugin {
protected:
    // Overridden from zeek::plugin::Plugin.
    zeek::plugin::Configuration Configure() override;

    void InitPostScript() override;

    bool HookPublishEvent(zeek::cluster::Backend& backend, const std::string& topic,
                          zeek::cluster::detail::Event& event) override;

    bool HookQueueEvent(zeek::Event* event) override;

private:
    zeek::telemetry::HistogramPtr histogram;
};

extern Plugin plugin;

} // namespace Zeek_EventLatency
} // namespace plugin
