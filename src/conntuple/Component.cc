// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/conntuple/Component.h"

#include "zeek/Desc.h"
#include "zeek/conntuple/Builder.h"
#include "zeek/conntuple/Manager.h"

using namespace zeek::conntuple;

Component::Component(const std::string& name, factory_callback arg_factory, Tag::subtype_t arg_subtype)
    : plugin::Component(plugin::component::CONNTUPLE, name, arg_subtype, conntuple_mgr->GetTagType()),
      factory(std::move(arg_factory)) {}

void Component::Initialize() {
    InitializeTag();
    conntuple_mgr->RegisterComponent(this, "CONNTUPLE_");
}

void Component::DoDescribe(ODesc* d) const {
    if ( factory ) {
        d->Add("CONNTUPLE_");
        d->Add(CanonicalName());
        d->Add(", ");
    }

    d->Add(Enabled() ? "enabled" : "disabled");
}
