// See the file "COPYING" in the main distribution directory for copyright.

#include "ShuntUtil.h"

#include "zeek/IPAddr.h"
#include "zeek/Val.h"

#include "bpf/filter_common.h"

namespace zeek::plugin::detail::Zeek_XDP_Shunter {

std::optional<canonical_tuple> makeBPFMapTuple(zeek::RecordVal* cid_r) {
    const zeek::IPAddr& ip1_val = cid_r->GetFieldAs<zeek::AddrVal>(0);
    uint16_t ip1_port = cid_r->GetFieldAs<zeek::PortVal>(1)->Port();
    const zeek::IPAddr& ip2_val = cid_r->GetFieldAs<zeek::AddrVal>(2);
    uint16_t ip2_port = cid_r->GetFieldAs<zeek::PortVal>(3)->Port();
    uint8_t proto = cid_r->GetFieldAs<zeek::CountVal>(4);

    in6_addr ip1;
    ip1_val.CopyIPv6(&ip1);
    in6_addr ip2;
    ip2_val.CopyIPv6(&ip2);

    uint16_t outer_vlan_id = cid_r->HasField(5) ? cid_r->GetFieldAs<zeek::CountVal>(5) : 0;
    uint16_t inner_vlan_id = cid_r->HasField(6) ? cid_r->GetFieldAs<zeek::CountVal>(6) : 0;

    canonical_tuple tup;
    memset(&tup, 0, sizeof(tup)); // Zero out padding too

    tup.ip1 = ip1;
    tup.ip2 = ip2;
    tup.port1 = ip1_port;
    tup.port2 = ip2_port;
    tup.protocol = proto;
    tup.outer_vlan_id = outer_vlan_id;
    tup.inner_vlan_id = inner_vlan_id;

    return tup;
}

ip_pair_key makeIPPairKey(zeek::RecordVal* pair_r) {
    in6_addr ip1;
    pair_r->GetFieldAs<AddrVal>(0).CopyIPv6(&ip1);
    in6_addr ip2;
    pair_r->GetFieldAs<AddrVal>(1).CopyIPv6(&ip2);
    uint16_t outer_vlan_id = pair_r->HasField(2) ? pair_r->GetFieldAs<zeek::CountVal>(2) : 0;
    uint16_t inner_vlan_id = pair_r->HasField(3) ? pair_r->GetFieldAs<zeek::CountVal>(3) : 0;

    auto ip2_higher = compare_ips(&ip1, &ip2) < 0;

    struct ip_pair_key pair;
    memset(&pair, 0, sizeof(pair)); // Zero out padding too

    pair.ip1 = ip2_higher ? ip1 : ip2;
    pair.ip2 = ip2_higher ? ip2 : ip1;
    pair.outer_vlan_id = outer_vlan_id;
    pair.inner_vlan_id = inner_vlan_id;

    return pair;
}

// Probably a better way to do this.
zeek::RecordValPtr makeEmptyShuntedStats() {
    static auto shunt_stats_type = zeek::id::find_type<zeek::RecordType>("XDP::ShuntedStats");

    auto stats = zeek::make_intrusive<zeek::RecordVal>(shunt_stats_type);
    stats->Assign(0, 0); // packets_from_1
    stats->Assign(1, 0); // bytes_from_1
    stats->Assign(2, 0); // packets_from_2
    stats->Assign(3, 0); // bytes_from_2
    // Timestamp is optional
    stats->Assign(5, false); // present

    return stats;
}

double monoToWall(uint64_t bpf_monotonic_ns) {
    // TODO: Should this use zeek's current_time? Probably! :)
    struct timespec real_now;
    clock_gettime(CLOCK_REALTIME, &real_now);
    uint64_t real_now_ns = (uint64_t)real_now.tv_sec * 1000000000 + real_now.tv_nsec;

    struct timespec mono_now;
    clock_gettime(CLOCK_MONOTONIC, &mono_now);
    uint64_t mono_now_ns = (uint64_t)mono_now.tv_sec * 1000000000 + mono_now.tv_nsec;

    uint64_t delta_ns = mono_now_ns - bpf_monotonic_ns;

    uint64_t packet_wall_time_ns = real_now_ns - delta_ns;

    // Convert to double-of-seconds
    return (double)packet_wall_time_ns / 1e9;
}

// The boolean decides which way ip1 was in the map
zeek::RecordValPtr makeShuntedStats(bool orig_is_ip1, const shunt_val* val) {
    static auto shunt_stats_type = zeek::id::find_type<zeek::RecordType>("XDP::ShuntedStats");
    auto stats = zeek::make_intrusive<zeek::RecordVal>(shunt_stats_type);

    if ( orig_is_ip1 ) {
        stats->Assign(0, static_cast<uint64_t>(val->packets_from_1));
        stats->Assign(1, static_cast<uint64_t>(val->bytes_from_1));
        stats->Assign(2, static_cast<uint64_t>(val->packets_from_2));
        stats->Assign(3, static_cast<uint64_t>(val->bytes_from_2));
    }
    else {
        stats->Assign(0, static_cast<uint64_t>(val->packets_from_2));
        stats->Assign(1, static_cast<uint64_t>(val->bytes_from_2));
        stats->Assign(2, static_cast<uint64_t>(val->packets_from_1));
        stats->Assign(3, static_cast<uint64_t>(val->bytes_from_1));
    }

    if ( val->timestamp != 0 ) {
        double packet_wall_time = monoToWall(val->timestamp);
        stats->AssignTime(4, packet_wall_time);
    }

    stats->Assign(5, true);

    return stats;
}

bool origIsIp1(zeek::RecordVal* cid_r) {
    const zeek::IPAddr& orig_h = cid_r->GetFieldAs<zeek::AddrVal>(0);
    const zeek::IPAddr& resp_h = cid_r->GetFieldAs<zeek::AddrVal>(2);

    in6_addr ip1;
    orig_h.CopyIPv6(&ip1);
    in6_addr ip2;
    resp_h.CopyIPv6(&ip2);

    // TODO: Check if this is accurate, might be flipped
    return compare_ips(&ip1, &ip2) < 0;
}

// Stolen from conn key factory
std::pair<int, int> GetVlanConnCtxFieldOffsets() {
    static int vlan_offset = -2;
    static int inner_vlan_offset = -2;

    if ( vlan_offset == -2 && inner_vlan_offset == -2 ) {
        vlan_offset = zeek::id::conn_id_ctx->FieldOffset("vlan");
        if ( vlan_offset < 0 || zeek::id::conn_id_ctx->GetFieldType(vlan_offset)->Tag() != zeek::TYPE_INT )
            vlan_offset = -1;

        inner_vlan_offset = zeek::id::conn_id_ctx->FieldOffset("inner_vlan");
        if ( inner_vlan_offset < 0 || zeek::id::conn_id_ctx->GetFieldType(inner_vlan_offset)->Tag() != zeek::TYPE_INT )
            inner_vlan_offset = -1;
    }

    return {vlan_offset, inner_vlan_offset};
}

zeek::RecordValPtr connIDToCanonical(zeek::RecordVal* conn_id, bool vlans_included) {
    static auto canonical_id = zeek::id::find_type<zeek::RecordType>("XDP::canonical_id");
    auto canonical = zeek::make_intrusive<zeek::RecordVal>(canonical_id);

    if ( origIsIp1(conn_id) ) {
        canonical->Assign(0, conn_id->GetField(0));
        canonical->Assign(1, conn_id->GetField(1));
        canonical->Assign(2, conn_id->GetField(2));
        canonical->Assign(3, conn_id->GetField(3));
    }
    else {
        canonical->Assign(0, conn_id->GetField(2));
        canonical->Assign(1, conn_id->GetField(3));
        canonical->Assign(2, conn_id->GetField(0));
        canonical->Assign(3, conn_id->GetField(1));
    }
    canonical->Assign(4, conn_id->GetField(4));

    if ( ! vlans_included )
        return canonical;

    auto [vlan_offset, inner_vlan_offset] = GetVlanConnCtxFieldOffsets();

    // Not present, that's fine but weird.
    if ( vlan_offset < 0 || inner_vlan_offset < 0 )
        return canonical;

    auto ctx = conn_id->GetFieldAs<zeek::RecordVal>(5);

    if ( ctx->HasField(vlan_offset) )
        canonical->Assign(5, ctx->GetFieldAs<zeek::IntVal>(vlan_offset));

    if ( ctx->HasField(inner_vlan_offset) )
        canonical->Assign(6, ctx->GetFieldAs<zeek::IntVal>(inner_vlan_offset));

    return canonical;
}

} // namespace zeek::plugin::detail::Zeek_XDP_Shunter
