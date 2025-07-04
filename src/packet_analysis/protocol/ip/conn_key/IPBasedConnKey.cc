// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/packet_analysis/protocol/ip/conn_key/IPBasedConnKey.h"

#include "zeek/Conn.h"

using namespace zeek;
using namespace zeek::packet_analysis::IP;

void IPBasedConnKey::InitTuple(const IPAddr& src_addr, uint32_t src_port, const IPAddr& dst_addr, uint32_t dst_port,
                               uint16_t proto, bool is_one_way) {
    auto& tuple = PackedTuple();

    if ( is_one_way || addr_port_canon_lt(src_addr, src_port, dst_addr, dst_port) ) {
        src_addr.CopyIPv6(&tuple.ip1);
        dst_addr.CopyIPv6(&tuple.ip2);
        tuple.port1 = src_port;
        tuple.port2 = dst_port;
        flipped = false;
    }
    else {
        dst_addr.CopyIPv6(&tuple.ip1);
        src_addr.CopyIPv6(&tuple.ip2);
        tuple.port1 = dst_port;
        tuple.port2 = src_port;
        flipped = true;
    }

    tuple.proto = proto;
}
