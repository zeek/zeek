
#include "Plugin.h"

#include <zeek/Event.h>
#include <zeek/Val.h>
#include <zeek/cluster/Backend.h>
#include <zeek/plugin/Plugin.h>
#include <zeek/telemetry/Manager.h>

namespace plugin {
namespace Zeek_EventLatency {
Plugin plugin;
}
} // namespace plugin

using namespace plugin::Zeek_EventLatency;

zeek::plugin::Configuration Plugin::Configure() {
    zeek::plugin::Configuration config;
    config.name = "Zeek::EventLatency";
    config.description = "Track remote event latencies";
    config.version = {0, 1, 0};
    EnableHook(zeek::plugin::HOOK_PUBLISH_EVENT);
    EnableHook(zeek::plugin::HOOK_QUEUE_EVENT);
    return config;
}

void Plugin::InitPostScript() {
    double bounds[] = {0.0002, 0.0004, 0.0006, 0.0008, 0.0010, 0.0012, 0.0014, 0.0016, 0.0018, 0.0020};
    histogram =
        zeek::telemetry_mgr->HistogramInstance("zeek", "cluster_event_latency_seconds", {}, bounds, "event latency");
}

bool Plugin::HookPublishEvent(zeek::cluster::Backend& backend, const std::string& topic,
                              zeek::cluster::detail::Event& event) {
    static const auto& wallclock_id = zeek::id::find_val<zeek::EnumVal>("EventLatency::WALLCLOCK_TIMESTAMP");

    auto now_val = zeek::make_intrusive<zeek::TimeVal>(zeek::util::current_time(/*real=*/true));

    if ( ! event.AddMetadata(wallclock_id, now_val) )
        zeek::reporter->FatalError("failed to add wallclock timestamp metadata");

    return true;
}

bool Plugin::HookQueueEvent(zeek::Event* event) {
    static const auto& wallclock_id = zeek::id::find_val<zeek::EnumVal>("EventLatency::WALLCLOCK_TIMESTAMP");

    if ( event->Source() == zeek::util::detail::SOURCE_LOCAL )
        return false;

    auto timestamps = event->MetadataValues(wallclock_id);

    if ( timestamps->Size() > 0 ) {
        double remote_ts = timestamps->ValAt(0)->AsTime();
        auto now = zeek::util::current_time(/*real=*/true);
        auto latency = std::max(0.0, now - remote_ts);

        histogram->Observe(latency);
    }
    else
        zeek::reporter->Warning("missing wallclock timestamp metadata");

    return false;
}
