
#include "Plugin.h"

#include <zeek/Desc.h>
#include <zeek/Event.h>
#include <zeek/Func.h>
#include <zeek/threading/Formatter.h>
#include <cstdlib>

namespace btest::plugin::Demo_Meta_Hooks {
Plugin plugin;
}

using namespace btest::plugin::Demo_Meta_Hooks;

zeek::plugin::Configuration Plugin::Configure() {
    zeek::plugin::Configuration config;
    config.name = "Demo::Meta_Hooks";
    config.description = "Test if the meta hooks are working";
    config.version.major = 1;
    config.version.minor = 0;
    config.version.patch = 0;

    // This plugin enables HookQueueEvent() and optionally the pre and post
    // meta hooks controlled by environment variables for easier testing.

    EnableHook(zeek::plugin::HOOK_QUEUE_EVENT);

    if ( getenv("TEST_META_HOOK_PRE") )
        EnableHook(zeek::plugin::META_HOOK_PRE);

    if ( getenv("TEST_META_HOOK_POST") )
        EnableHook(zeek::plugin::META_HOOK_POST);

    return config;
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


bool Plugin::HookQueueEvent(zeek::Event* e) {
    fprintf(stdout, "%.6f %-15s %s()\n", zeek::run_state::network_time, "  HookQueueEvent", e->Handler()->Name());
    return false;
}

void Plugin::MetaHookPre(zeek::plugin::HookType hook, const zeek::plugin::HookArgumentList& args) {
    // The spicy integration enables HOOK_LOAD_FILE and this plugin receives
    // meta hooks also for that :-/
    if ( hook != zeek::plugin::HOOK_QUEUE_EVENT )
        return;

    zeek::ODesc d;
    d.SetShort();
    describe_hook_args(args, &d);
    fprintf(stdout, "%.6f %-15s %s(%s)\n", zeek::run_state::network_time, "  MetaHookPre", hook_name(hook),
            d.Description());
}

void Plugin::MetaHookPost(zeek::plugin::HookType hook, const zeek::plugin::HookArgumentList& args,
                          zeek::plugin::HookArgument result) {
    // The spicy integration enables HOOK_LOAD_FILE and this plugin receives
    // meta hooks also for that :-/
    if ( hook != zeek::plugin::HOOK_QUEUE_EVENT )
        return;

    zeek::ODesc d1;
    zeek::ODesc d2;
    describe_hook_args(args, &d1);
    result.Describe(&d2);

    fprintf(stdout, "%.6f %-15s %s(%s) -> %s\n", zeek::run_state::network_time, "  MetaHookPost", hook_name(hook),
            d1.Description(), d2.Description());
}
