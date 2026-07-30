// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/conn_key/Factory.h"

#include <netinet/in.h>

#include "zeek/IP.h"
#include "zeek/iosource/Packet.h"

namespace zeek::conn_key {

namespace {

struct FragmentKeyData {
    in6_addr src;
    in6_addr dst;
    uint32_t id = 0;
} __attribute__((packed, aligned));

} // namespace

session::detail::Key Factory::DoFragmentKey(const Packet& /* pkt */, const IP_Hdr& ip) const {
    FragmentKeyData key;
    ip.SrcAddr().CopyIPv6(&key.src);
    ip.DstAddr().CopyIPv6(&key.dst);
    key.id = ip.ID();

    return {&key, sizeof(key), session::detail::Key::FRAGMENT_KEY_TYPE, true};
}

} // namespace zeek::conn_key
