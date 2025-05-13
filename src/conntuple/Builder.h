// See the file "COPYING" in the main distribution directory for copyright.
#pragma once

#include "zeek/Conn.h"

namespace zeek {

class Packet;
class RecordVal;
using RecordValPtr = IntrusivePtr<RecordVal>;

namespace conntuple {

class Builder;
using BuilderPtr = std::unique_ptr<Builder>;

/**
 * Fill an IPBasedConnKey from a Zeek script value.
 */
bool fill_from_val(const IPBasedConnKey* k, const zeek::ValPtr& v);

class Builder {
public:
    Builder();
    virtual ~Builder();

    // TODO: Should these better be abstract?
    virtual zeek::ConnKeyPtr NewConnKey();
    virtual zeek::ConnKeyPtr FromVal(const zeek::ValPtr& v);

    static zeek::conntuple::BuilderPtr Instantiate() { return std::make_unique<Builder>(); }
};

} // namespace conntuple
} // namespace zeek
