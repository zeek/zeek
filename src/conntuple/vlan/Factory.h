// See the file "COPYING" in the main distribution directory for copyright.
#pragma once

#include "zeek/ConnKey.h"
#include "zeek/conntuple/fivetuple/Factory.h"

namespace zeek::conntuple::vlan {

class Factory : public zeek::conntuple::fivetuple::Factory {
public:
    /**
     * Instantiates a clean ConnKey derivative and returns it.
     * @return A unique pointer to the ConnKey instance.
     */
    zeek::ConnKeyPtr NewConnKey() override;

    /**
     * Instantiates a filled-in ConnKey derivative from a script-layer
     * record, usually a conn_id instance. Implementations are free to
     * implement this liberally, i.e. the input does not _have_ to be a
     * conn_id.
     *
     * @param v The script-layer value providing key input.
     * @return A unique pointer to the ConnKey instance.
     */
    zeek::ConnKeyPtr FromVal(const zeek::ValPtr& v) override;

    static zeek::conntuple::FactoryPtr Instantiate() { return std::make_unique<Factory>(); }
};

} // namespace zeek::conntuple::vlan
