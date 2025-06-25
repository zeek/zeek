// See the file "COPYING" in the main distribution directory for copyright.
#pragma once

#include "zeek/ConnKey.h"
#include "zeek/util-types.h"

namespace zeek {

class Packet;
class RecordVal;
using RecordValPtr = IntrusivePtr<RecordVal>;

namespace conn_key {

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
     *
     * @return A unique pointer to the ConnKey instance.
     */
    zeek::ConnKeyPtr NewConnKey() const { return DoNewConnKey(); }

    /**
     * Instantiates a filled-in ConnKey derivative from a script-layer
     * record, usually a conn_id instance. Implementations are free to
     * implement this liberally, i.e. the input does not _have_ to be a
     * conn_id.
     *
     * @param v The script-layer value providing key input.
     * @return A unique pointer to the ConnKey instance, or an error message.
     */
    zeek::expected<zeek::ConnKeyPtr, std::string> ConnKeyFromVal(const zeek::Val& v) const {
        return DoConnKeyFromVal(v);
    }

protected:
    /**
     * Hook for Factory::NewConnKey.
     *
     * @return A unique pointer to the ConnKey instance.
     */
    virtual zeek::ConnKeyPtr DoNewConnKey() const = 0;

    /**
     * Hook for Factory::ConnKeyFromVal.
     *
     * @return A unique pointer to the ConnKey instance, or an error message.
     */
    virtual zeek::expected<zeek::ConnKeyPtr, std::string> DoConnKeyFromVal(const zeek::Val& v) const = 0;
};

} // namespace conn_key
} // namespace zeek
