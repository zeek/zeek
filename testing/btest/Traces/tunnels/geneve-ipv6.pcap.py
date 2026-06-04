#!/usr/bin/env python3
"""
Generate geneve-ipv6.pcap: an IPv6/UDP exchange encapsulated directly inside
Geneve (Protocol Type = 0x86DD), with no inner Ethernet frame.

This exposes a typo in scripts/base/packet-protocols/geneve/main.zeek where
the Geneve -> IP dispatch for IPv6 was registered under 0x08DD instead of
the real IPv6 ethertype 0x86DD. With the typo in place, the inner IPv6
flow is not analyzed and never appears in conn.log.
"""

from pathlib import Path

from scapy.all import IP, UDP, Ether, IPv6, Raw, wrpcap
from scapy.contrib.geneve import GENEVE

GENEVE_PORT = 6081
ETHERTYPE_IPV6 = 0x86DD


def geneve_ipv6_packet(
    outer_src, outer_dst, outer_sport, inner_src, inner_dst, sport, dport, payload
):
    inner = (
        IPv6(src=inner_src, dst=inner_dst, hlim=64)
        / UDP(sport=sport, dport=dport)
        / Raw(payload)
    )
    return (
        Ether()
        / IP(src=outer_src, dst=outer_dst)
        / UDP(sport=outer_sport, dport=GENEVE_PORT)
        / GENEVE(vni=0x123456, proto=ETHERTYPE_IPV6)
        / inner
    )


def main():
    pkts = [
        geneve_ipv6_packet(
            "10.0.0.1",
            "10.0.0.2",
            12345,
            "fd00::1",
            "fd00::2",
            40000,
            40001,
            b"hello",
        ),
        geneve_ipv6_packet(
            "10.0.0.1",
            "10.0.0.2",
            12345,
            "fd00::2",
            "fd00::1",
            40001,
            40000,
            b"world",
        ),
    ]

    out = Path(__file__).with_suffix("")
    wrpcap(str(out), pkts)
    print(f"Wrote {len(pkts)} packets to {out}")


if __name__ == "__main__":
    main()
