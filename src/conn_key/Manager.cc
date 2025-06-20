// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/conn_key/Manager.h"

#include "zeek/conn_key/Component.h"

using namespace zeek::conn_key;

Manager::Manager() : plugin::ComponentManager<zeek::conn_key::Component>("ConnKey", "Tag") {}

void Manager::InitPostScript() {
    const auto& factory_val = id::find_val<zeek::EnumVal>("ConnKey::factory");
    factory = InstantiateFactory(factory_val);
}

FactoryPtr Manager::InstantiateFactory(const zeek::EnumValPtr& tag) {
    Component* c = Lookup(tag);

    if ( ! c ) {
        reporter->FatalError(
            "request to instantiate unknown connection tuple factory %s, please review ConnTuple::factory value",
            tag->GetType()->AsEnumType()->Lookup(tag->Get()));
    }

    if ( ! c->Factory() ) {
        reporter->FatalError("factory %s cannot be instantiated dynamically", GetComponentName(tag).c_str());
    }

    FactoryPtr factory = c->Factory()();

    if ( ! factory ) {
        reporter->FatalError("factory instantiation failed");
    }

    // Could add validation of actual tag vs obtained one here, as we do e.g. in
    // the packet_analysis Manager.

    return factory;
}
