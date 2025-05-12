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

class Builder {
public:
    Builder();
    virtual ~Builder();

    virtual zeek::ConnKeyPtr NewConnKey();

    static zeek::conntuple::BuilderPtr Instantiate() { return std::make_unique<Builder>(); }
};

} // namespace conntuple
} // namespace zeek
