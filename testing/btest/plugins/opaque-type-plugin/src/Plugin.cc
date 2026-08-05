#include "Plugin.h"

#include <zeek/Desc.h>
#include <zeek/Scope.h>
#include <zeek/Val.h>

#include "NanoTime.h"

namespace btest::plugin::Demo_Foo {
Plugin plugin;
}

using namespace btest::plugin::Demo_Foo;

zeek::plugin::Configuration Plugin::Configure() {
    zeek::plugin::Configuration config;
    config.name = "Demo::Foo";
    config.description = "A custom OpaqueType class";
    config.version.major = 1;
    config.version.minor = 0;
    config.version.patch = 0;
    return config;
}

void Plugin::InitPreScript() {
    using btest::type::NanoTimeOpaqueType;
    fprintf(stderr, "Plugin::InitPreScript()\n");
    NanoTimeOpaqueType::type_ptr = zeek::make_intrusive<btest::type::NanoTimeOpaqueType>();

    // Install the new type as "NanoTime" type by hand.
    NanoTimeOpaqueType::id_ptr = zeek::detail::install_ID("NanoTime", "GLOBAL", /*is_global=*/true, /*is_export=*/true);
    NanoTimeOpaqueType::id_ptr->MakeType();
    NanoTimeOpaqueType::id_ptr->SetType(NanoTimeOpaqueType::type_ptr);
}

// Run some tests at InitPostScript() time.
void Plugin::InitPostScript() {
    fprintf(stderr, "Plugin::InitPostScript()\n");
    using btest::type::NanoTimeOpaqueType;

    // Create a type for set[opaque of NanoTime]
    auto tl = zeek::make_intrusive<zeek::TypeList>();
    tl->Append(NanoTimeOpaqueType::type_ptr);
    auto tt = zeek::make_intrusive<zeek::TableType>(tl, /*yield=*/nullptr);

    // This is a set[opaque of Nanotime]
    auto tv = zeek::make_intrusive<zeek::TableVal>(tt);

    std::fprintf(stdout, "Plugin::InitPostScript() tv=%s\n", zeek::obj_desc_short(tv).c_str());

    auto nanos1 = zeek::make_intrusive<btest::type::NanoTimeVal>(42);
    auto nanos2 = zeek::make_intrusive<btest::type::NanoTimeVal>(4711);

    if ( ! tv->Assign(nanos1, nullptr) )
        zeek::reporter->InternalError("failed to insert nanos1");

    if ( ! tv->Assign(nanos2, nullptr) )
        zeek::reporter->InternalError("failed to insert nanos2");

    std::fprintf(stdout, "Plugin::InitPostScript() tv=%s\n", zeek::obj_desc_short(tv).c_str());
}

void Plugin::Done() {
    // Just finalization.
    fprintf(stdout, "Plugin::Done()\n");
}
