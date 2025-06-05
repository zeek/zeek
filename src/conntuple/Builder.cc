// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/conntuple/Builder.h"

#include "zeek/Conn.h"
#include "zeek/ID.h"
#include "zeek/IPAddr.h"
#include "zeek/session/Session.h"

namespace zeek::conntuple {

Builder::Builder() {}
Builder::~Builder() {}

ConnTuplePtr Builder::GetTuple(const Packet* pkt) { return std::make_shared<ConnTuple>(); }

zeek::detail::ConnKeyPtr Builder::GetKey(const ConnTuple& tuple) {
    return std::make_shared<zeek::detail::ConnKey>(tuple);
}

zeek::detail::ConnKeyPtr Builder::GetKey(Val* v) { return std::make_shared<zeek::detail::ConnKey>(v); }

} // namespace zeek::conntuple
