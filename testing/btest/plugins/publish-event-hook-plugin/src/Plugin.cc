
#include "Plugin.h"

#include <zeek/Desc.h>
#include <zeek/cluster/Backend.h>
#include <cstdio>
#include <string>

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

bool Plugin::HookPublishEvent(const std::string& topic, zeek::cluster::detail::Event& event) {
    static const auto& string_meta = zeek::id::find_val<zeek::EnumVal>("App::MY_STRING_META");
    static const auto& table_meta = zeek::id::find_val<zeek::EnumVal>("App::MY_TABLE_META");
    static const auto& unreg = zeek::id::find_val<zeek::EnumVal>("App::MY_UNREG_META");

    std::fprintf(stdout, "%.6f %-15s %s(%s)\n", zeek::run_state::network_time, "  HookPublishEvent", topic.c_str(),
                 std::string(event.HandlerName()).c_str());

    if ( topic == "/do/not/publish" )
        return false;

    // String metadata.
    bool result;
    result = event.AddMetadata(string_meta, zeek::make_intrusive<zeek::StringVal>("A string"));
    if ( ! result )
        zeek::reporter->FatalError("Failed to add string metadata");

    // Table metadata
    const auto& table_sos = zeek::id::find_type<zeek::TableType>("table_string_of_string");
    auto tv = zeek::make_intrusive<zeek::TableVal>(table_sos);
    tv->Assign(zeek::make_intrusive<zeek::StringVal>("key1"), zeek::make_intrusive<zeek::StringVal>("value1"));
    result = event.AddMetadata(table_meta, tv);
    if ( ! result )
        zeek::reporter->FatalError("Failed to add string metadata");

    // Test adding the wrong type.
    result = event.AddMetadata(string_meta, zeek::val_mgr->Count(42));
    if ( result )
        zeek::reporter->FatalError("Succeeded adding unregistered metadata");

    // Test adding unregistered metadata.
    result = event.AddMetadata(unreg, zeek::val_mgr->Count(42));
    if ( result )
        zeek::reporter->FatalError("Succeeded adding unregistered metadata");

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
