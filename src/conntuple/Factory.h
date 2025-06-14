// See the file "COPYING" in the main distribution directory for copyright.
#pragma once

#include "zeek/ConnKey.h"
#include "zeek/conntuple/Manager.h"

namespace zeek {

class Packet;
class RecordVal;
using RecordValPtr = IntrusivePtr<RecordVal>;

namespace conntuple {

class Factory;
using FactoryPtr = std::unique_ptr<Factory>;

/**
 * ConnKey factories instantiate derivatives of ConnKeys, to provide pluggable flow hashing.
 */
class Factory {
public:
    virtual ~Factory() = default;

    /**
     * Instantiates a clean ConnKey derivative and returns it.
     * @return A unique pointer to the ConnKey instance.
     */
    virtual zeek::ConnKeyPtr NewConnKey() = 0;

    /**
     * Instantiates a filled-in ConnKey derivative from a script-layer
     * record, usually a conn_id instance. Implementations are free to
     * implement this liberally, i.e. the input does not _have_ to be a
     * conn_id.
     *
     * @param v The script-layer value providing key input.
     * @return A unique pointer to the ConnKey instance.
     */
    virtual zeek::ConnKeyPtr FromVal(const zeek::ValPtr& v) = 0;
};

} // namespace conntuple
} // namespace zeek
