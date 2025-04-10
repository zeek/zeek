// See the file "COPYING" in the main distribution directory for copyright.
#pragma once

#include "zeek/Conn.h"
#include "zeek/IPAddr.h"
#include "zeek/conntuple/Manager.h"

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

    virtual ConnTuplePtr GetTuple(const Packet* pkt);

    virtual zeek::detail::ConnKeyPtr GetKey(const ConnTuple& tuple);
    virtual zeek::detail::ConnKeyPtr GetKey(Val* v);

    virtual void FillConnIdVal(detail::ConnKeyPtr key, RecordValPtr& tuple) {};

    static zeek::conntuple::BuilderPtr Instantiate() { return std::make_unique<Builder>(); }
};

} // namespace conntuple
} // namespace zeek
