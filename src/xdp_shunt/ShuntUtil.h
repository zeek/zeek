#pragma once

#include <optional>

#include "zeek/IPAddr.h"
#include "zeek/Val.h"

#include "bpf/filter_common.h"

struct in6_addr addrToIpVal(const zeek::IPAddr& addr);
std::optional<canonical_tuple> makeBPFMapTuple(zeek::RecordVal* cid_r);
ip_pair_key makeIPPairKey(zeek::RecordVal* pair_r);
zeek::RecordValPtr makeCanonicalTuple(const canonical_tuple&);
zeek::RecordValPtr makeIPPair(const ip_pair_key&);
zeek::RecordValPtr makeEmptyShuntedStats();
double mono_to_wall(uint64_t bpf_monotonic_ns);
zeek::RecordValPtr makeShuntedStats(bool orig_is_ip1, const shunt_val* val);
zeek::RecordValPtr makeCanonicalConnId(const canonical_tuple&);
bool origIsIp1(zeek::RecordVal* cid_r);
