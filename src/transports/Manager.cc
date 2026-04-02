// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/transports/Manager.h"

#include "zeek/Reporter.h"

using namespace zeek;
using namespace zeek::transports;

Manager* transport_mgr = nullptr;

Manager::Manager() : plugin::ComponentManager<Component>("TransportProto", "Tag") {}

void Manager::RegisterProtos(const zeek::Tag& tag, const std::set<uint8_t>& protos) {
    for ( uint8_t p : protos ) {
        if ( proto_to_tag.contains(p) ) {
            reporter->FatalError("Tag for protocol number %d exists", p);
            return;
        }

        proto_to_tag.insert({p, tag});
    }
}

zeek::Tag Manager::LookupByProto(uint8_t proto) const {
    if ( auto it = proto_to_tag.find(proto); it != proto_to_tag.end() )
        return it->second;

    return GetComponentTag("UNKNOWN_TRANSPORT");
}

uint8_t Manager::GetPrimaryProto(const zeek::Tag& tag) const {
    auto* component = Lookup(tag);
    if ( ! component || component->GetProtos().empty() )
        return 0;

    // TODO: This isn't really the "primary" port. It's whatever port is at the
    // front of the set, based on how the values got hashed.
    return *component->GetProtos().begin();
}

uint32_t Manager::GetPortMask(const zeek::Tag& tag) const {
    if ( auto* component = Lookup(tag) )
        return component->GetPortMask();

    // TODO: is this valid?
    return 0;
}
