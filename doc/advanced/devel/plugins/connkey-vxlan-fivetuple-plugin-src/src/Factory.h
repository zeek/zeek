#pragma once

#include "zeek/ConnKey.h"
#include "zeek/packet_analysis/protocol/ip/conn_key/fivetuple/Factory.h"

namespace zeek::conn_key::vxlan_vni_fivetuple {

class Factory : public zeek::conn_key::fivetuple::Factory {
public:
    static zeek::conn_key::FactoryPtr Instantiate() { return std::make_unique<Factory>(); }

private:
    // Returns a VxlanVniConnKey instance.
    zeek::ConnKeyPtr DoNewConnKey() const override;
    zeek::expected<zeek::ConnKeyPtr, std::string> DoConnKeyFromVal(const zeek::Val& v) const override;
};

} // namespace zeek::conn_key::vxlan_vni_fivetuple
