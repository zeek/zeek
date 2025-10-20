#include "ShuntUtil.h"

#include "zeek/IPAddr.h"
#include "zeek/Val.h"

#include "XDPProgram.h"
#include "bpf/filter_common.h"

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
    const zeek::IPAddr& orig_h = cid_r->GetFieldAs<zeek::AddrVal>(0);
    uint16_t orig_p = cid_r->GetFieldAs<zeek::PortVal>(1)->Port();
    const zeek::IPAddr& resp_h = cid_r->GetFieldAs<zeek::AddrVal>(2);
    uint16_t resp_p = cid_r->GetFieldAs<zeek::PortVal>(3)->Port();
    uint8_t proto = cid_r->GetFieldAs<zeek::CountVal>(4);

    auto ip1 = addrToIpVal(orig_h);
    auto ip2 = addrToIpVal(resp_h);

    auto tup = canonical_tuple{
        .ip1 = ip1,
        .ip2 = ip2,
        .port1 = orig_p,
        .port2 = resp_p,
        .protocol = proto,
    };

    // We order first by ip, or if they're equal, by port.
    if ( compare_ips(&tup.ip1, &tup.ip2) > 0 || ((compare_ips(&tup.ip1, &tup.ip2) == 0) && tup.port1 > tup.port2) ) {
        // Flip them, they're out of order
        std::swap(tup.ip1, tup.ip2);
        std::swap(tup.port1, tup.port2);
    }

    return tup;
}

// Probably a better way to do this.
zeek::RecordValPtr makeEmptyShuntedStats() {
    static auto shunt_stats_type = zeek::id::find_type<zeek::RecordType>("XDP::ShuntedStats");

    auto stats = zeek::make_intrusive<zeek::RecordVal>(shunt_stats_type);
    stats->Assign(0, zeek::val_mgr->Count(0));
    stats->Assign(1, zeek::val_mgr->Count(0));
    stats->Assign(2, zeek::val_mgr->Count(0));
    stats->Assign(3, zeek::val_mgr->Count(0));
    stats->Assign(4, zeek::val_mgr->Count(0));
    stats->Assign(5, zeek::val_mgr->Count(0));
    // Timestamp is optional
    stats->Assign(7, zeek::val_mgr->Bool(false));

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

    stats->Assign(4, zeek::val_mgr->Count(val->fin));
    stats->Assign(5, zeek::val_mgr->Count(val->rst));

    if ( val->timestamp != 0 ) {
        double packet_wall_time = mono_to_wall(val->timestamp);
        stats->Assign(6, zeek::make_intrusive<zeek::TimeVal>(packet_wall_time));
    }

    stats->Assign(7, zeek::val_mgr->Bool(true));

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
