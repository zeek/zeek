// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/packet_analysis/protocol/ip/ConnKey.h"

using namespace zeek;
using namespace zeek::packet_analysis::IP;

std::optional<std::string> IPBasedConnKey::Error() const {
    auto& rt = PackedTuple();
    if ( rt.proto == detail::INVALID_CONN_KEY_IP_PROTO )
        return "invalid connection ID record encountered";
    if ( rt.proto == UNKNOWN_IP_PROTO )
        return "invalid connection ID record encountered: the proto field has the \"unknown\" 65535 value. "
               "Did you forget to set it?";

    return std::nullopt;
}
