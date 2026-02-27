#include "ShuntUtil.h"

#include <zeek/Event.h>
#include <zeek/IPAddr.h>
#include <zeek/Val.h>
#include <zeek/session/Manager.h>

#include "bpf/UserXDP.h"
#include "bpf/filter_common.h"
#include "conn_id_shunter.bif.h"

struct in6_addr addrToIpVal(const zeek::IPAddr& addr) {
    const uint32_t* bytes;
    int len = addr.GetBytes(&bytes);
    struct in6_addr ip = {0};
    if ( len == 1 ) {
        ip.s6_addr[10] = 0xff;
        ip.s6_addr[11] = 0xff;
        memcpy(&ip.s6_addr[12], &bytes[0], sizeof(uint32_t));
    }
    else
        memcpy(&ip, bytes, sizeof(struct in6_addr));

    return ip;
}

std::optional<canonical_tuple> makeBPFMapTuple(zeek::RecordVal* cid_r) {
    const zeek::IPAddr& ip1_val = cid_r->GetFieldAs<zeek::AddrVal>(0);
    uint16_t ip1_port = cid_r->GetFieldAs<zeek::PortVal>(1)->Port();
    const zeek::IPAddr& ip2_val = cid_r->GetFieldAs<zeek::AddrVal>(2);
    uint16_t ip2_port = cid_r->GetFieldAs<zeek::PortVal>(3)->Port();
    uint8_t proto = cid_r->GetFieldAs<zeek::CountVal>(4);

    auto ip1 = addrToIpVal(ip1_val);
    auto ip2 = addrToIpVal(ip2_val);

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
    auto ip1 = addrToIpVal(pair_r->GetFieldAs<zeek::AddrVal>(0));
    auto ip2 = addrToIpVal(pair_r->GetFieldAs<zeek::AddrVal>(1));
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

zeek::AddrValPtr makeAddr(struct in6_addr ip) {
    if ( IN6_IS_ADDR_V4MAPPED(&ip) )
        return zeek::make_intrusive<zeek::AddrVal>(*reinterpret_cast<const uint32_t*>(&ip.s6_addr[12]));
    else
        return zeek::make_intrusive<zeek::AddrVal>(reinterpret_cast<const uint32_t*>(&ip.s6_addr));
}

zeek::RecordValPtr makeCanonicalTuple(const canonical_tuple& tup) {
    static auto canonical_id = zeek::id::find_type<zeek::RecordType>("XDP::canonical_id");
    auto zeek_key = zeek::make_intrusive<zeek::RecordVal>(canonical_id);
    zeek_key->Assign(0, makeAddr(tup.ip1));
    zeek_key->Assign(1, zeek::val_mgr->Port(tup.port1));

    zeek_key->Assign(2, makeAddr(tup.ip2));
    zeek_key->Assign(3, zeek::val_mgr->Port(tup.port2));

    zeek_key->Assign(4, zeek::val_mgr->Count(tup.protocol));

    return zeek_key;
}

zeek::RecordValPtr makeCanonicalConnId(const canonical_tuple& canonical) {
    // Stole this idea from fivetuple factory, it's easy :)
    constexpr int orig_h = 0;
    constexpr int orig_p = 1;
    constexpr int resp_h = 2;
    constexpr int resp_p = 3;
    constexpr int proto = 4;

    // orig and resp do not matter!
    auto cid = zeek::make_intrusive<zeek::RecordVal>(zeek::id::conn_id);
    cid->Assign(orig_h, makeAddr(canonical.ip1));
    cid->Assign(orig_p, zeek::val_mgr->Port(canonical.port1));

    cid->Assign(resp_h, makeAddr(canonical.ip2));
    cid->Assign(resp_p, zeek::val_mgr->Port(canonical.port2));

    cid->Assign(proto, zeek::val_mgr->Count(canonical.protocol));

    // TODO: VLANs!
    return cid;
}

// Probably a better way to do this.
zeek::RecordValPtr makeEmptyShuntedStats() {
    static auto shunt_stats_type = zeek::id::find_type<zeek::RecordType>("XDP::ShuntedStats");

    auto stats = zeek::make_intrusive<zeek::RecordVal>(shunt_stats_type);
    stats->Assign(0, zeek::val_mgr->Count(0)); // packets_from_1
    stats->Assign(1, zeek::val_mgr->Count(0)); // bytes_from_1
    stats->Assign(2, zeek::val_mgr->Count(0)); // packets_from_2
    stats->Assign(3, zeek::val_mgr->Count(0)); // bytes_from_2
    // Timestamp is optional
    stats->Assign(5, zeek::val_mgr->Bool(false)); // present

    return stats;
}

double mono_to_wall(uint64_t bpf_monotonic_ns) {
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
        stats->Assign(0, zeek::val_mgr->Count(val->packets_from_1));
        stats->Assign(1, zeek::val_mgr->Count(val->bytes_from_1));
        stats->Assign(2, zeek::val_mgr->Count(val->packets_from_2));
        stats->Assign(3, zeek::val_mgr->Count(val->bytes_from_2));
    }
    else {
        stats->Assign(0, zeek::val_mgr->Count(val->packets_from_2));
        stats->Assign(1, zeek::val_mgr->Count(val->bytes_from_2));
        stats->Assign(2, zeek::val_mgr->Count(val->packets_from_1));
        stats->Assign(3, zeek::val_mgr->Count(val->bytes_from_1));
    }

    if ( val->timestamp != 0 ) {
        double packet_wall_time = mono_to_wall(val->timestamp);
        stats->Assign(4, zeek::make_intrusive<zeek::TimeVal>(packet_wall_time));
    }

    stats->Assign(5, zeek::val_mgr->Bool(true));

    return stats;
}

bool origIsIp1(zeek::RecordVal* cid_r) {
    const zeek::IPAddr& orig_h = cid_r->GetFieldAs<zeek::AddrVal>(0);
    const zeek::IPAddr& resp_h = cid_r->GetFieldAs<zeek::AddrVal>(2);

    auto ip1 = addrToIpVal(orig_h);
    auto ip2 = addrToIpVal(resp_h);

    // TODO: Check if this is accurate, might be flipped
    return compare_ips(&ip1, &ip2) < 0;
}
