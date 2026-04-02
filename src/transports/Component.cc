// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/transports/Component.h"

#include "zeek/Desc.h"
#include "zeek/plugin/Component.h"
#include "zeek/transports/Manager.h"

using namespace zeek::transports;

Component::Component(std::string_view name, std::set<uint8_t> proto_numbers, uint32_t port_mask, Tag::subtype_t subtype)
    : zeek::plugin::Component(plugin::component::TRANSPORT_PROTO, std::string{name}, subtype),
      proto_numbers(std::move(proto_numbers)),
      mask(port_mask) {}

void Component::Initialize() {
    InitializeTag();
    manager->RegisterComponent(this, "TransportProto::");
    manager->RegisterProtos(Tag(), proto_numbers);
}

void Component::DoDescribe(ODesc* d) const {
    d->Add("TransportProto::");
    d->Add(Name());
}
