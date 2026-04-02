// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <cstdint>
#include <set>
#include <string_view>

#include "zeek/Tag.h"
#include "zeek/plugin/Component.h"

namespace zeek::transports {

class Component : public plugin::Component {
public:
    Component(std::string_view name, std::set<uint8_t> proto_numbers, uint32_t port_mask = 0,
              Tag::subtype_t subtype = 0);

    void Initialize() override;

    const std::set<uint8_t>& GetProtos() const { return proto_numbers; }
    uint32_t GetPortMask() const { return mask; }

protected:
    void DoDescribe(ODesc* d) const override;

private:
    std::set<uint8_t> proto_numbers;
    uint32_t mask;
};

} // namespace zeek::transports
