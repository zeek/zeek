#include <optional>

#include "zeek/IPAddr.h"
#include "zeek/Val.h"

#include "bpf/filter_common.h"

struct in6_addr addrToIpVal(const zeek::IPAddr& addr);
std::optional<canonical_tuple> makeBPFMapTuple(zeek::RecordVal* cid_r);
zeek::RecordValPtr makeEmptyShuntedStats();
double mono_to_wall(uint64_t bpf_monotonic_ns);
zeek::RecordValPtr makeShuntedStats(bool orig_is_ip1, const shunt_val* val);
bool origIsIp1(zeek::RecordVal* cid_r);
