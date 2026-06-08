#!/usr/bin/env python3
"""
Generate a pcap with truncated ICMPv6 NDP packets that exercise
the length checks added before BuildNDOptionsVal calls in ICMP.cc.

Each packet is truncated so that caplen (bytes after the 8-byte ICMPv6
header) is shorter than the expected option offset:
  - Router Advertisement: opt_offset = 8 (reachable_time + retrans_timer)
  - Neighbor Advertisement: opt_offset = 16 (target address)
  - Neighbor Solicitation: opt_offset = 16 (target address)
  - Redirect: opt_offset = 32 (target + destination addresses)
"""

import struct

from scapy.all import (
    Ether,
    ICMPv6ND_NA,
    ICMPv6ND_NS,
    ICMPv6ND_RA,
    ICMPv6ND_Redirect,
    ICMPv6NDOptSrcLLAddr,
    IPv6,
    PcapWriter,
    raw,
)


def _icmpv6_checksum(src_bytes, dst_bytes, icmpv6_data):
    """Compute ICMPv6 checksum per RFC 2463 using the IPv6 pseudo-header."""
    # Pseudo-header: src (16) + dst (16) + upper-layer length (4) + zeros (3) + next header (1)
    plen = len(icmpv6_data)
    pseudo = src_bytes + dst_bytes + struct.pack("!I", plen) + b"\x00\x00\x00\x3a"
    data = pseudo + icmpv6_data
    if len(data) % 2:
        data += b"\x00"
    total = 0
    for i in range(0, len(data), 2):
        total += (data[i] << 8) + data[i + 1]
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def truncate_icmpv6_payload(pkt, keep_icmp_payload_bytes):
    """Build a packet where the ICMPv6 body is truncated to
    `keep_icmp_payload_bytes` after the 8-byte ICMPv6 header.
    The IPv6 payload length and ICMPv6 checksum are recomputed
    so Zeek accepts the packet without flagging truncation or
    bad checksums."""
    full = raw(pkt)
    eth_len = 14
    ipv6_hdr_len = 40
    icmp_hdr_len = 8
    cut_at = eth_len + ipv6_hdr_len + icmp_hdr_len + keep_icmp_payload_bytes
    truncated = bytearray(full[:cut_at])

    # Fix IPv6 Payload Length (2 bytes at offset 4 in IPv6 header)
    new_plen = icmp_hdr_len + keep_icmp_payload_bytes
    truncated[eth_len + 4] = (new_plen >> 8) & 0xFF
    truncated[eth_len + 5] = new_plen & 0xFF

    # Recompute ICMPv6 checksum over the truncated content
    icmp_start = eth_len + ipv6_hdr_len
    # Zero the checksum field before computing
    truncated[icmp_start + 2] = 0
    truncated[icmp_start + 3] = 0
    src_bytes = bytes(truncated[eth_len + 8 : eth_len + 24])
    dst_bytes = bytes(truncated[eth_len + 24 : eth_len + 40])
    icmpv6_data = bytes(truncated[icmp_start:])
    cksum = _icmpv6_checksum(src_bytes, dst_bytes, icmpv6_data)
    truncated[icmp_start + 2] = (cksum >> 8) & 0xFF
    truncated[icmp_start + 3] = cksum & 0xFF

    return bytes(truncated)


def main():
    output = "icmp6-nd-short-options.pcap"
    writer = PcapWriter(output, linktype=1, sync=True)

    src_mac = "00:11:22:33:44:55"
    dst_mac = "00:66:77:88:99:aa"
    src_ip = "fe80::1"
    dst_ip = "fe80::2"
    target = "fe80::3"

    # --- Router Advertisement: opt_offset = 8 (sizeof(uint32_t)*2) ---
    # Truncate to 4 bytes of payload (less than 8) to trigger icmp6_ra_bad_opt_offset
    ra = (
        Ether(src=src_mac, dst=dst_mac)
        / IPv6(src=src_ip, dst="ff02::1")
        / ICMPv6ND_RA()
    )
    writer.write(Ether(truncate_icmpv6_payload(ra, 4)))

    # Also include a valid RA for comparison (full payload with options)
    ra_good = (
        Ether(src=src_mac, dst=dst_mac)
        / IPv6(src=src_ip, dst="ff02::1")
        / ICMPv6ND_RA()
        / ICMPv6NDOptSrcLLAddr(lladdr=src_mac)
    )
    writer.write(ra_good)

    # --- Neighbor Advertisement: opt_offset = 16 (sizeof(in6_addr)) ---
    # Truncate to 8 bytes of payload (less than 16) to trigger icmp6_na_bad_opt_offset
    na = (
        Ether(src=src_mac, dst=dst_mac)
        / IPv6(src=src_ip, dst=dst_ip)
        / ICMPv6ND_NA(tgt=target)
    )
    writer.write(Ether(truncate_icmpv6_payload(na, 8)))

    # Valid NA
    na_good = (
        Ether(src=src_mac, dst=dst_mac)
        / IPv6(src=src_ip, dst=dst_ip)
        / ICMPv6ND_NA(tgt=target)
        / ICMPv6NDOptSrcLLAddr(lladdr=src_mac)
    )
    writer.write(na_good)

    # --- Neighbor Solicitation: opt_offset = 16 (sizeof(in6_addr)) ---
    # Truncate to 8 bytes of payload (less than 16) to trigger icmp6_ns_bad_opt_offset
    ns = (
        Ether(src=src_mac, dst=dst_mac)
        / IPv6(src=src_ip, dst="ff02::1:ff00:3")
        / ICMPv6ND_NS(tgt=target)
    )
    writer.write(Ether(truncate_icmpv6_payload(ns, 8)))

    # Valid NS
    ns_good = (
        Ether(src=src_mac, dst=dst_mac)
        / IPv6(src=src_ip, dst="ff02::1:ff00:3")
        / ICMPv6ND_NS(tgt=target)
        / ICMPv6NDOptSrcLLAddr(lladdr=src_mac)
    )
    writer.write(ns_good)

    # --- Redirect: opt_offset = 32 (2 * sizeof(in6_addr)) ---
    # Truncate to 16 bytes of payload (less than 32) to trigger icmp6_redirect_bad_opt_offset
    redirect = (
        Ether(src=src_mac, dst=dst_mac)
        / IPv6(src=src_ip, dst=dst_ip)
        / ICMPv6ND_Redirect(tgt=target, dst="2001:db8::1")
    )
    writer.write(Ether(truncate_icmpv6_payload(redirect, 16)))

    # Valid Redirect
    redirect_good = (
        Ether(src=src_mac, dst=dst_mac)
        / IPv6(src=src_ip, dst=dst_ip)
        / ICMPv6ND_Redirect(tgt=target, dst="2001:db8::1")
        / ICMPv6NDOptSrcLLAddr(lladdr=src_mac)
    )
    writer.write(redirect_good)

    # --- Edge cases: payload exactly at the boundary (should NOT trigger) ---
    # RA with exactly 8 bytes payload (just enough)
    writer.write(Ether(truncate_icmpv6_payload(ra, 8)))

    # NA with exactly 16 bytes payload (just enough)
    writer.write(Ether(truncate_icmpv6_payload(na, 16)))

    # NS with exactly 16 bytes payload (just enough)
    ns_full_hdr = (
        Ether(src=src_mac, dst=dst_mac)
        / IPv6(src=src_ip, dst="ff02::1:ff00:3")
        / ICMPv6ND_NS(tgt=target)
    )
    writer.write(Ether(truncate_icmpv6_payload(ns_full_hdr, 16)))

    # Redirect with exactly 32 bytes payload (just enough)
    writer.write(Ether(truncate_icmpv6_payload(redirect, 32)))

    # --- Zero-length payloads (most extreme truncation) ---
    # Note: Zeek deduplicates net-level weirds by name, so these won't
    # produce additional weird.log entries unless sampling is disabled.
    # They still exercise the code path.
    ra_zero = (
        Ether(src=src_mac, dst=dst_mac)
        / IPv6(src="fe80::10", dst="ff02::1")
        / ICMPv6ND_RA()
    )
    writer.write(Ether(truncate_icmpv6_payload(ra_zero, 0)))

    na_zero = (
        Ether(src=src_mac, dst=dst_mac)
        / IPv6(src="fe80::10", dst=dst_ip)
        / ICMPv6ND_NA(tgt=target)
    )
    writer.write(Ether(truncate_icmpv6_payload(na_zero, 0)))

    ns_zero = (
        Ether(src=src_mac, dst=dst_mac)
        / IPv6(src="fe80::10", dst="ff02::1:ff00:3")
        / ICMPv6ND_NS(tgt=target)
    )
    writer.write(Ether(truncate_icmpv6_payload(ns_zero, 0)))

    redirect_zero = (
        Ether(src=src_mac, dst=dst_mac)
        / IPv6(src="fe80::10", dst=dst_ip)
        / ICMPv6ND_Redirect(tgt=target, dst="2001:db8::1")
    )
    writer.write(Ether(truncate_icmpv6_payload(redirect_zero, 0)))

    writer.close()
    print(f"Wrote {output}")


if __name__ == "__main__":
    main()
