// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/conntuple/Manager.h"

using namespace zeek::conntuple;

Manager::Manager() : plugin::ComponentManager<conntuple::Component>("ConnTuple", "Tag") {}

void Manager::InitPostScript() {
    const auto& builder_val = id::find_val<zeek::EnumVal>("ConnTuple::builder");
    builder = InstantiateBuilder(builder_val);
}

BuilderPtr Manager::InstantiateBuilder(const zeek::EnumValPtr& tag) {
    Component* c = Lookup(tag);

    if ( ! c ) {
        reporter->FatalError(
            "request to instantiate unknown connection tuple builder %s, please review ConnTuple::builder value",
            tag->GetType()->AsEnumType()->Lookup(tag->Get()));
    }

    if ( ! c->Factory() ) {
        reporter->FatalError("builder %s cannot be instantiated dynamically", GetComponentName(tag).c_str());
    }

    BuilderPtr builder = c->Factory()();

    if ( ! builder ) {
        reporter->FatalError("builder instantiation failed");
    }

    // Could add validation of actual tag vs obtained one here, as we do e.g. in
    // the packet_analysis Manager.

    return builder;
}
