
#include "Plugin.h"

#include <zeek/Desc.h>
#include <zeek/ID.h>
#include <zeek/Reporter.h>
#include <zeek/Val.h>
#include <zeek/cluster/Backend.h>
#include <cstdio>
#include <string>

namespace btest::plugin::Demo_PublishEventMetadata {
Plugin plugin;
}

using namespace btest::plugin::Demo_PublishEventMetadata;

zeek::plugin::Configuration Plugin::Configure() {
    EnableHook(zeek::plugin::HOOK_PUBLISH_EVENT);

    zeek::plugin::Configuration config;
    config.name = "Demo::PublishEventMetadata";
    config.description = "For testing metadata publish";
    config.version.major = 1;
    config.version.minor = 0;
    config.version.patch = 0;
    return config;
}

void Plugin::InitPostScript() {
    std::fprintf(stdout, "%.6f %-15s\n", zeek::run_state::network_time, "  InitPostScript");
}

bool Plugin::HookPublishEvent(zeek::cluster::Backend& backend, const std::string& topic,
                              zeek::cluster::detail::Event& event) {
    std::fprintf(stdout, "%.6f %s backend=%s topic=%s event=%s\n", zeek::run_state::network_time, "HookPublishEvent",
                 backend.Name().c_str(), topic.c_str(), std::string(event.HandlerName()).c_str());

    const auto& table_type = zeek::id::find_type<zeek::TableType>("table_string_of_string");
    const auto& string_md = zeek::id::find_val<zeek::EnumVal>("App::CUSTOM_METADATA_STRING");
    auto count_md = zeek::id::find_val<zeek::EnumVal>("App::CUSTOM_METADATA_COUNT");
    auto table_md = zeek::id::find_val<zeek::EnumVal>("App::CUSTOM_METADATA_TABLE");

    if ( ! count_md || ! table_md )
        zeek::reporter->FatalError("Could not find required enum values");

    if ( topic == "topic1" ) {
        if ( ! event.AddMetadata(string_md, zeek::make_intrusive<zeek::StringVal>("testing string metadata")) ) {
            zeek::reporter->FatalError("Failed to add string metadata");
        }
    }
    else if ( topic == "topic2" ) {
        if ( ! event.AddMetadata(count_md, zeek::val_mgr->Count(42424242)) ) {
            zeek::reporter->FatalError("Failed to add count metadata");
        }
    }
    else if ( topic == "topic3" ) {
        auto tv = zeek::make_intrusive<zeek::TableVal>(table_type);
        if ( ! tv->Assign(zeek::make_intrusive<zeek::StringVal>("key1"),
                          zeek::make_intrusive<zeek::StringVal>("val1")) )
            zeek::reporter->FatalError("Could not update table value");

        if ( ! event.AddMetadata(table_md, tv) ) {
            zeek::reporter->FatalError("Failed to add table metadata");
        }
    }
    else if ( topic == "topic4" ) {
        auto tv = zeek::make_intrusive<zeek::TableVal>(table_type);
        if ( ! tv->Assign(zeek::make_intrusive<zeek::StringVal>("key1"),
                          zeek::make_intrusive<zeek::StringVal>("val1")) )
            zeek::reporter->FatalError("Could not update table value");

        if ( ! event.AddMetadata(table_md, tv) ) {
            zeek::reporter->FatalError("Failed to add table metadata");
        }

        if ( ! event.AddMetadata(count_md, zeek::val_mgr->Count(41414242)) ) {
            zeek::reporter->FatalError("Failed to add string metadata");
        }

        if ( ! event.AddMetadata(string_md, zeek::make_intrusive<zeek::StringVal>("testing string metadata")) ) {
            zeek::reporter->FatalError("Failed to add string metadata");
        }

        // Event metadata is just a vector, so can have duplicate entries.
        if ( ! event.AddMetadata(string_md, zeek::make_intrusive<zeek::StringVal>("more string metadata")) ) {
            zeek::reporter->FatalError("Failed to add string metadata");
        }
    }
    else {
        zeek::reporter->FatalError("Unhandled topic %s", topic.c_str());
    }


    return true;
}
