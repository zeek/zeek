// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/conn_key/Component.h"

#include "zeek/Desc.h"
#include "zeek/conn_key/Manager.h"

using namespace zeek::conn_key;

Component::Component(const std::string& name, factory_callback arg_factory, Tag::subtype_t arg_subtype)
    : plugin::Component(plugin::component::CONNKEY, name, arg_subtype, conn_key_mgr->GetTagType()),
      factory(std::move(arg_factory)) {}

void Component::Initialize() {
    InitializeTag();
    conn_key_mgr->RegisterComponent(this, "CONNKEY_");
}

void Component::DoDescribe(ODesc* d) const {
    if ( factory ) {
        d->Add("CONNKEY_");
        d->Add(CanonicalName());
        d->Add(", ");
    }

    d->Add(Enabled() ? "enabled" : "disabled");
}
