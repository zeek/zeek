#include "Plugin.h"

#include <cstdio>

#include "zeek/Desc.h"
#include "zeek/Frame.h"
#include "zeek/Func.h"
#include "zeek/Scope.h"
#include "zeek/Val.h"

namespace plugin {
namespace Demo_Foo {
Plugin plugin;
}
} // namespace plugin

using namespace plugin::Demo_Foo;

zeek::plugin::Configuration Plugin::Configure() {
    zeek::plugin::Configuration config;

    std::printf("Configure()\n");

    return config;
}

static zeek::ValPtr LoadSo__call_me(zeek::detail::Frame* f, const zeek::Args* args) {
    std::printf("LoadSo__call_me: args=%zu args[0]=%s\n", args->size(), zeek::obj_desc_short((*args)[0]).c_str());
    return (*args)[0];
}

void Plugin::InitPreScript() {
    std::printf("InitPreScript()\n");

    // Install a BuiltinFunc at load time.
    auto call_me_id = zeek::detail::global_scope()->Find("LoadSo::call_me");
    if ( ! call_me_id )
        zeek::reporter->FatalError("Could not find LoadSo::call_me identifier");

    // Populate the declared LoadSo::call_me identifier with a FuncVal that holds
    // a BuiltinFunc instance that'll call the static LoadSo__call_me() above.
    auto call_me_func =
        zeek::make_intrusive<zeek::detail::BuiltinFunc>(&LoadSo__call_me, "LoadSo::call_me", /*is_pure=*/false);
    auto call_me_val = zeek::make_intrusive<zeek::FuncVal>(std::move(call_me_func));
    call_me_id->SetVal(std::move(call_me_val));

    std::printf("Installed value for LoadSo::call_me()\n");
}

void Plugin::InitPostScript() { std::printf("InitPostScript()\n"); }

void Plugin::Done() { std::printf("Done()\n"); }
