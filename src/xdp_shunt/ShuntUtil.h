// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <optional>

#include "zeek/Val.h"

#include "bpf/filter_common.h"

namespace zeek::plugin::detail::Zeek_XDP_Shunter {

// Since the BPF map stores the monotonic clock time, we need to convert it
// to wall clock time.
double monoToWall(uint64_t bpf_monotonic_ns);

// Whether the originator is ip1 in a sorted canonical tuple.
bool origIsIp1(zeek::RecordVal* cid_r);

// Make the canonical tuple used within a BPF map from the conn ID.
std::optional<canonical_tuple> makeBPFMapTuple(zeek::RecordVal* cid_r);

// Make the IP pair key used within a BPF map from the IP pair script val.
ip_pair_key makeIPPairKey(zeek::RecordVal* pair_r);

// Make empty shunted statistics that are labelled as not present.
zeek::RecordValPtr makeEmptyShuntedStats();

// Make shunted stats from the value of the BPF map.
zeek::RecordValPtr makeShuntedStats(bool orig_is_ip1, const shunt_val* val);

// Transform a conn ID into a canonical ID, optionally with VLANs.
zeek::RecordValPtr connIDToCanonical(zeek::RecordVal* conn_id, bool vlans_included);

} // namespace zeek::plugin::detail::Zeek_XDP_Shunter
