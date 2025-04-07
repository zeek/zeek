
#include "Plugin.h"

#include <iostream>

#include "zeek/ID.h"
#include "zeek/Reporter.h"
#include "zeek/Type.h"
#include "zeek/Val.h"

namespace btest::plugin::Demo_API {
Plugin plugin;
}

using namespace btest::plugin::Demo_API;

zeek::plugin::Configuration Plugin::Configure() {
    zeek::plugin::Configuration config;
    config.name = "Demo::API";
    config.description = "Use some of Zeek's API for testing";
    config.version.major = 1;
    config.version.minor = 0;
    config.version.patch = 0;
    return config;
}

namespace {

// Test zeek::id::find for enums an their types.
void TestEnumIdentifiers() {
    auto severity_type = zeek::id::find_type<zeek::EnumType>("DemoAPI::Severity");
    if ( ! severity_type )
        zeek::reporter->FatalError("DemoAPI::Severity not found");

    // Expect 5 entries!
    if ( severity_type->Names().size() != 5 )
        zeek::reporter->FatalError("Wrong number of severities %" PRId64, severity_type->Names().size());

    // Ensure CRITICAL and USER_DEBUG identifiers have the same enum type as severity_type.
    auto critical_id = zeek::id::find("DemoAPI::CRITICAL");
    auto critical_type = critical_id->GetType();
    auto user_debug_id = zeek::id::find("User::USER_DEBUG");
    auto user_debug_type = user_debug_id->GetType();

    if ( critical_type != user_debug_type )
        zeek::reporter->FatalError("CRITICAL and USER_DEBUG have different types (%p and %p)", critical_type.get(),
                                   user_debug_type.get());

    // Ensure the critical_id and user_debug_type IDs have an EnumVal attached
    // and that the value is the same as in script land.
    auto critical_val = critical_id->GetVal();
    auto user_debug_val = user_debug_id->GetVal();

    if ( ! critical_val || ! user_debug_val )
        zeek::reporter->FatalError("Missing values on enum value identifiers %p %p", critical_val.get(),
                                   user_debug_val.get());

    if ( critical_val->AsEnum() != 1 )
        zeek::reporter->FatalError("Wrong value for CRITICAL: %" PRId64, critical_val->AsEnum());

    if ( user_debug_val->AsEnum() != 50 )
        zeek::reporter->FatalError("Wrong value for USER_DEBUG: %" PRId64, user_debug_val->AsEnum());

    // Ensure all the types (identifiers and values) agree with severity_type.
    if ( critical_type != severity_type )
        zeek::reporter->FatalError("CRITICAL identifier has the wrong enum type %p vs %p", critical_type.get(),
                                   severity_type.get());

    if ( user_debug_type != severity_type )
        zeek::reporter->FatalError("USER_DEBUG identifier has the wrong enum type %p vs %p", user_debug_type.get(),
                                   severity_type.get());

    if ( critical_val->GetType() != severity_type )
        zeek::reporter->FatalError("CRITICAL value has the wrong enum type %p vs %p", critical_val->GetType().get(),
                                   severity_type.get());

    if ( user_debug_val->GetType() != severity_type )
        zeek::reporter->FatalError("USER_DEBUG value has the wrong enum type %p vs %p", user_debug_val->GetType().get(),
                                   severity_type.get());

    std::cout << "TestEnumIdentifiers successful" << std::endl;
}

} // namespace

void Plugin::InitPostScript() {
    // Other API tests if wanted.
    TestEnumIdentifiers();
}
