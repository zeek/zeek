// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/net_util.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <memory>

#include "zeek/IP.h"
#include "zeek/IPAddr.h"
#include "zeek/Reporter.h"

#include "zeek/3rdparty/doctest.h"

const char* transport_proto_string(TransportProto proto) {
    switch ( proto ) {
        case TRANSPORT_TCP: return "tcp";
        case TRANSPORT_UDP: return "udp";
        case TRANSPORT_ICMP: return "icmp";
        case TRANSPORT_UNKNOWN:
        default: return "unknown";
    }
}

namespace zeek {

uint16_t detail::ip4_in_cksum(const IPAddr& src, const IPAddr& dst, uint8_t next_proto, const uint8_t* data, int len) {
    constexpr auto nblocks = 2;
    detail::checksum_block blocks[nblocks];

    ipv4_pseudo_hdr ph;
    memset(&ph, 0, sizeof(ph));

    src.CopyIPv4(&ph.src);
    dst.CopyIPv4(&ph.dst);
    ph.len = htons(static_cast<uint16_t>(len));
    ph.next_proto = next_proto;
    blocks[0].block = reinterpret_cast<const uint8_t*>(&ph);
    blocks[0].len = sizeof(ph);
    blocks[1].block = data;
    blocks[1].len = len;

    return in_cksum(blocks, nblocks);
}

uint16_t detail::ip6_in_cksum(const IPAddr& src, const IPAddr& dst, uint8_t next_proto, const uint8_t* data, int len) {
    constexpr auto nblocks = 2;
    detail::checksum_block blocks[nblocks];

    ipv6_pseudo_hdr ph;
    memset(&ph, 0, sizeof(ph));

    src.CopyIPv6(&ph.src);
    dst.CopyIPv6(&ph.dst);
    ph.len = htonl(static_cast<uint32_t>(len));
    ph.next_proto = next_proto;
    blocks[0].block = reinterpret_cast<const uint8_t*>(&ph);
    blocks[0].len = sizeof(ph);
    blocks[1].block = data;
    blocks[1].len = len;

    return in_cksum(blocks, nblocks);
}

// Returns the ones-complement checksum of a chunk of 'b' bytes.
int ones_complement_checksum(const void* p, int b, uint32_t sum) {
    const unsigned char* sp = reinterpret_cast<const unsigned char*>(p);

    b /= 2; // convert to count of short's

    /* No need for endian conversions. */
    while ( --b >= 0 ) {
        sum += *sp + (*(sp + 1) << 8);
        sp += 2;
    }

    while ( sum > 0xffff )
        sum = (sum & 0xffff) + (sum >> 16);

    return sum;
}

int ones_complement_checksum(const IPAddr& a, uint32_t sum) {
    const uint32_t* bytes;
    int len = a.GetBytes(&bytes);
    return ones_complement_checksum(bytes, len * 4, sum);
}

int icmp_checksum(const struct icmp* icmpp, int len) {
    return detail::in_cksum(reinterpret_cast<const uint8_t*>(icmpp), len);
}

int mobility_header_checksum(const IP_Hdr* ip) {
    const ip6_mobility* mh = ip->MobilityHeader();

    if ( ! mh )
        return 0;

    uint32_t sum = 0;
    uint8_t mh_len = 8 + 8 * mh->ip6mob_len;

    if ( mh_len % 2 == 1 )
        reporter->Weird(ip->SrcAddr(), ip->DstAddr(), "odd_mobility_hdr_len");

    sum = ones_complement_checksum(ip->SrcAddr(), sum);
    sum = ones_complement_checksum(ip->DstAddr(), sum);
    // Note, for IPv6, strictly speaking the protocol and length fields are
    // 32 bits rather than 16 bits.  But because the upper bits are all zero,
    // we get the same checksum either way.
    sum += htons(IPPROTO_MOBILITY);
    sum += htons(mh_len);
    sum = ones_complement_checksum(mh, mh_len, sum);

    return sum;
}

int icmp6_checksum(const struct icmp* icmpp, const IP_Hdr* ip, int len) {
    // ICMP6 uses the same checksum function as ICMP4 but a different
    // pseudo-header over which it is computed.
    return detail::ip6_in_cksum(ip->SrcAddr(), ip->DstAddr(), IPPROTO_ICMPV6, reinterpret_cast<const uint8_t*>(icmpp),
                                len);
}

constexpr uint32_t CLASS_A = 0x00000000;
constexpr uint32_t CLASS_B = 0x80000000;
constexpr uint32_t CLASS_C = 0xc0000000;
constexpr uint32_t CLASS_D = 0xe0000000;
constexpr uint32_t CLASS_E = 0xf0000000;

char addr_to_class(uint32_t addr) {
    auto CHECK_CLASS = [](uint32_t addr, uint32_t cls) { return (addr & cls) == cls; };
    if ( CHECK_CLASS(addr, CLASS_E) )
        return 'E';
    else if ( CHECK_CLASS(addr, CLASS_D) )
        return 'D';
    else if ( CHECK_CLASS(addr, CLASS_C) )
        return 'C';
    else if ( CHECK_CLASS(addr, CLASS_B) )
        return 'B';
    else
        return 'A';
}

const char* fmt_conn_id(const IPAddr& src_addr, uint32_t src_port, const IPAddr& dst_addr, uint32_t dst_port) {
    static char buffer[512];

    snprintf(buffer, sizeof(buffer), "%s:%d > %s:%d", std::string(src_addr).c_str(), src_port,
             std::string(dst_addr).c_str(), dst_port);

    return buffer;
}

const char* fmt_conn_id(const uint32_t* src_addr, uint32_t src_port, const uint32_t* dst_addr, uint32_t dst_port) {
    IPAddr src(IPv6, src_addr, IPAddr::Network);
    IPAddr dst(IPv6, dst_addr, IPAddr::Network);
    return fmt_conn_id(src, src_port, dst, dst_port);
}

TEST_CASE("fmt_mac") {
    auto my_fmt_mac = [](const char* m, int len) {
        // allow working with literal strings
        return fmt_mac(reinterpret_cast<const unsigned char*>(m), len);
    };

    CHECK(my_fmt_mac("", 0) == "");
    CHECK(my_fmt_mac("\x01\x02\x03\x04\x05\x06", 4) == "");
    CHECK(my_fmt_mac("\x01\x02\x03\x04\x05\x06", 6) == "01:02:03:04:05:06");
    // NOLINTNEXTLINE(bugprone-string-literal-with-embedded-nul)
    CHECK(my_fmt_mac("\x01\x02\x03\x04\x05\x06\x00\x00", 8) == "01:02:03:04:05:06");
    CHECK(my_fmt_mac("\x01\x02\x03\x04\x05\x06\x07\x08", 8) == "01:02:03:04:05:06:07:08");
    CHECK(my_fmt_mac("\x08\x07\x06\x05\x04\x03\x02\x01", 8) == "08:07:06:05:04:03:02:01");
}

std::string fmt_mac(const unsigned char* m, int len) {
    auto [mac_bytes, slen] = fmt_mac_bytes(m, len);
    return reinterpret_cast<char*>(mac_bytes.get());
}

TEST_CASE("fmt_mac_bytes") {
    auto my_fmt_mac_bytes = [](const char* m, int len) {
        // allow working with literal strings
        return fmt_mac_bytes(reinterpret_cast<const unsigned char*>(m), len);
    };

    auto [buf1, len1] = my_fmt_mac_bytes("\x01\x02\x03\x04\x05\x06", 4);
    CHECK(len1 == 0);
    CHECK(memcmp(buf1.get(), "", 1) == 0); // still null terminated

    auto [buf2, len2] = my_fmt_mac_bytes("\x01\x02\x03\x04\x05\x06", 6);
    CHECK(len2 == 2 * 6 + 5);
    CHECK(memcmp(buf2.get(), "01:02:03:04:05:06", len2 + 1) == 0);

    // NOLINTNEXTLINE(bugprone-string-literal-with-embedded-nul)
    auto [buf3, len3] = my_fmt_mac_bytes("\x01\x02\x03\x04\x05\x06\x00\x00", 8);
    CHECK(len3 == 2 * 6 + 5);
    CHECK(memcmp(buf3.get(), "01:02:03:04:05:06", len3 + 1) == 0);

    // Check for no memory overreads
    auto [buf4, len4] = my_fmt_mac_bytes("\x01\x02\x03\x04\x05\x06\x07\x08\xff\xff", 42);
    CHECK(len4 == 2 * 8 + 7);
    CHECK(memcmp(buf4.get(), "01:02:03:04:05:06:07:08", len4 + 1) == 0);
}

std::pair<std::unique_ptr<uint8_t[]>, int> fmt_mac_bytes(const unsigned char* m, int len) {
    if ( len < 8 && len != 6 ) {
        auto buf = std::make_unique<uint8_t[]>(1);
        buf[0] = '\0';
        return {std::move(buf), 0};
    }

    int elen = (len == 6 || (m[6] == 0 && m[7] == 0)) ? 6 : 8;
    auto slen = 2 * elen + (elen - 1);
    auto buf = std::make_unique<uint8_t[]>(slen + 1);
    auto* bufp = reinterpret_cast<char*>(buf.get());

    for ( int i = 0; i < elen; i++ ) {
        zeek::util::bytetohex(m[i], &bufp[i * 2 + i]);
        if ( i < elen - 1 )
            bufp[i * 2 + i + 2] = ':';
    }
    bufp[slen] = '\0';

    return {std::move(buf), slen};
}

uint32_t extract_uint32(const u_char* data) {
    uint32_t val;

    val = data[0] << 24;
    val |= data[1] << 16;
    val |= data[2] << 8;
    val |= data[3];

    return val;
}

} // namespace zeek
