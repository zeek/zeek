// See the file "COPYING" in the main distribution directory for copyright.
#pragma once

#include "zeek/ConnKey.h"
#include "zeek/packet_analysis/protocol/ip/conn_key/fivetuple/Factory.h"

namespace zeek::conn_key::vlan_fivetuple {

class Factory : public zeek::conn_key::fivetuple::Factory {
public:
    static zeek::conn_key::FactoryPtr Instantiate() { return std::make_unique<Factory>(); }

private:
    /**
     * Instantiates a clean ConnKey derivative and returns it.
     *
     * @return A unique pointer to the ConnKey instance.
     */
    zeek::ConnKeyPtr DoNewConnKey() const override;

    /**
     * Instantiates a filled-in ConnKey derivative from a script-layer
     * record, usually a conn_id instance. Implementations are free to
     * implement this liberally, i.e. the input does not _have_ to be a
     * conn_id.
     *
     * @param v The script-layer value providing key input.
     * @return A unique pointer to the ConnKey instance, or an error message.
     */
    zeek::expected<zeek::ConnKeyPtr, std::string> DoConnKeyFromVal(const zeek::Val& v) const override;
};

} // namespace zeek::conn_key::vlan_fivetuple
