
#include "Plugin.h"

#include "zeek/Conn.h"
#include "zeek/Desc.h"
#include "zeek/Event.h"
#include "zeek/Func.h"
#include "zeek/Val.h"
#include "zeek/threading/Formatter.h"

namespace btest::plugin::Demo_Hooks {
Plugin plugin;
}

using namespace btest::plugin::Demo_Hooks;

zeek::plugin::Configuration Plugin::Configure() {
    EnableHook(zeek::plugin::HOOK_CALL_FUNCTION);
    EnableHook(zeek::plugin::META_HOOK_PRE);
    EnableHook(zeek::plugin::META_HOOK_POST);

    zeek::plugin::Configuration config;
    config.name = "Demo::Hooks";
    config.description = "Exercises all plugin hooks";
    config.version.major = 1;
    config.version.minor = 0;
    config.version.patch = 0;
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

std::pair<bool, zeek::ValPtr> Plugin::HookFunctionCall(const zeek::Func* func, zeek::detail::Frame* frame,
                                                       zeek::Args* args) {
    zeek::ODesc d;
    d.SetShort();
    zeek::plugin::HookArgument(func).Describe(&d);
    zeek::plugin::HookArgument(args).Describe(&d);
    fprintf(stderr, "%.6f %-15s %s\n", zeek::run_state::network_time, "| HookFunctionCall", d.Description());

    if ( zeek::util::streq(func->Name(), "foo") ) {
        auto& vl = *args;
        vl[0] = zeek::val_mgr->Count(42);
    }

    return {};
}

void Plugin::MetaHookPre(zeek::plugin::HookType hook, const zeek::plugin::HookArgumentList& args) {
    zeek::ODesc d;
    d.SetShort();
    describe_hook_args(args, &d);
    fprintf(stderr, "%.6f %-15s %s(%s)\n", zeek::run_state::network_time, "  MetaHookPre", hook_name(hook),
            d.Description());
}

void Plugin::MetaHookPost(zeek::plugin::HookType hook, const zeek::plugin::HookArgumentList& args,
                          zeek::plugin::HookArgument result) {
    zeek::ODesc d1;
    d1.SetShort();
    describe_hook_args(args, &d1);

    zeek::ODesc d2;
    d2.SetShort();
    result.Describe(&d2);

    fprintf(stderr, "%.6f %-15s %s(%s) -> %s\n", zeek::run_state::network_time, "  MetaHookPost", hook_name(hook),
            d1.Description(), d2.Description());
}
