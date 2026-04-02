// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <unordered_map>

#include "zeek/Tag.h"
#include "zeek/plugin/ComponentManager.h"
#include "zeek/transports/Component.h"

namespace zeek::transports {

class Manager : public plugin::ComponentManager<Component> {
public:
    Manager();

    Tag LookupByProto(uint8_t proto) const;
    uint8_t GetPrimaryProto(const Tag& tag) const;
    uint32_t GetPortMask(const Tag& tag) const;

    void RegisterProtos(const Tag& tag, const std::set<uint8_t>& proto_numbers);

private:
    // Fast lookup: IP proto number -> transport tag
    std::unordered_map<uint8_t, zeek::Tag> proto_to_tag;
};

static Manager* manager;

} // namespace zeek::transports
