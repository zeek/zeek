// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/conntuple/Builder.h"

#include "zeek/packet_analysis/protocol/ip/IPBasedAnalyzer.h"

namespace zeek::conntuple {

Builder::Builder() {}
Builder::~Builder() {}

zeek::ConnKeyPtr Builder::NewConnKey() { return zeek::make_intrusive<zeek::IPConnKey>(); }

} // namespace zeek::conntuple
