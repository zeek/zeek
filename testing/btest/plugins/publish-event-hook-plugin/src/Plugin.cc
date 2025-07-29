
#include "Plugin.h"

#include <cstdio>
#include <string>

#include "zeek/Desc.h"
#include "zeek/cluster/Backend.h"

namespace btest::plugin::Demo_PublishEvent {
Plugin plugin;
}

using namespace btest::plugin::Demo_PublishEvent;

zeek::plugin::Configuration Plugin::Configure() {
    EnableHook(zeek::plugin::HOOK_PUBLISH_EVENT);
    EnableHook(zeek::plugin::META_HOOK_PRE);
    EnableHook(zeek::plugin::META_HOOK_POST);

    zeek::plugin::Configuration config;
    config.name = "Demo::PublishEvent";
    config.description = "Exercises hook for publishing events";
    config.version.major = 1;
    config.version.minor = 0;
    config.version.patch = 0;
    return config;
}

void Plugin::InitPostScript() {
    std::fprintf(stdout, "%.6f %-15s\n", zeek::run_state::network_time, "  InitPostScript");
}

static void describe_hook_args(const zeek::plugin::HookArgumentList& args, zeek::ODesc* d) {
    bool first = true;

    for ( const auto& arg : args ) {
        if ( ! first )
            d->Add(", ");

        arg.Describe(d);
        first = false;
    }
}

bool Plugin::HookPublishEvent(zeek::cluster::Backend& backend, const std::string& topic, zeek::cluster::Event& event) {
    std::fprintf(stdout, "%.6f %-15s backend=%s topic=%s event=%s\n", zeek::run_state::network_time,
                 "  HookPublishEvent", backend.Name().c_str(), topic.c_str(), std::string(event.HandlerName()).c_str());

    if ( topic == "/do/not/publish" )
        return false;

    std::fprintf(stdout, "%.6f %-15s %s(%s)\n", zeek::run_state::network_time, "  HookPublishEvent", topic.c_str(),
                 std::string(event.HandlerName()).c_str());

    return true;
}

void Plugin::MetaHookPre(zeek::plugin::HookType hook, const zeek::plugin::HookArgumentList& args) {
    if ( hook != zeek::plugin::HOOK_PUBLISH_EVENT )
        return;

    zeek::ODesc d;
    d.SetShort();
    describe_hook_args(args, &d);

    std::fprintf(stdout, "%.6f %-15s %s(%s)\n", zeek::run_state::network_time, "  MetaHookPre", hook_name(hook),
                 d.Description());
}

void Plugin::MetaHookPost(zeek::plugin::HookType hook, const zeek::plugin::HookArgumentList& args,
                          zeek::plugin::HookArgument result) {
    if ( hook != zeek::plugin::HOOK_PUBLISH_EVENT )
        return;

    zeek::ODesc d1;
    d1.SetShort();
    describe_hook_args(args, &d1);

    zeek::ODesc d2;
    d2.SetShort();
    result.Describe(&d2);

    std::fprintf(stdout, "%.6f %-15s %s(%s) -> %s\n", zeek::run_state::network_time, "  MetaHookPost", hook_name(hook),
                 d1.Description(), d2.Description());
}
