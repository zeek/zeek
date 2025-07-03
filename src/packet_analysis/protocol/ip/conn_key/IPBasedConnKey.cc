// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/packet_analysis/protocol/ip/conn_key/IPBasedConnKey.h"

#include "zeek/Conn.h"
#include "zeek/Desc.h"

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

void IPBasedConnKey::DoPopulateConnIdVal(RecordVal& conn_id, RecordVal& ctx) {
    if ( conn_id.GetType() != id::conn_id )
        zeek::reporter->InternalError("unexpected conn_id type %s", obj_desc_short(conn_id.GetType().get()).c_str());

    conn_id.Assign(0, make_intrusive<AddrVal>(SrcAddr()));
    conn_id.Assign(1, val_mgr->Port(ntohs(SrcPort()), GetTransportProto()));
    conn_id.Assign(2, make_intrusive<AddrVal>(DstAddr()));
    conn_id.Assign(3, val_mgr->Port(ntohs(DstPort()), GetTransportProto()));
}

void IPBasedConnKey::DoFlipRoles(RecordVal& conn_id, RecordVal& ctx) {
    if ( conn_id.GetType() != id::conn_id )
        zeek::reporter->InternalError("unexpected conn_id type %s", obj_desc_short(conn_id.GetType().get()).c_str());

    const auto& tmp_addr = conn_id.GetField<zeek::AddrVal>(0);
    const auto& tmp_port = conn_id.GetField<zeek::PortVal>(1);
    conn_id.Assign(0, conn_id.GetField<zeek::AddrVal>(2));
    conn_id.Assign(1, conn_id.GetField<zeek::PortVal>(3));
    conn_id.Assign(2, tmp_addr);
    conn_id.Assign(3, tmp_port);
}
