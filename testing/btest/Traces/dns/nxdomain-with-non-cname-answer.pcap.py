#!/usr/bin/env python3
"""Generate DNS test flows for NXDOMAIN responses with answer records.

Exercises:
1. RFC-violating NXDOMAIN response with a terminal TXT answer record (raises weird).
2. RFC-violating NXDOMAIN response with a terminal A answer record (raises weird).
3. Standard RFC 2308 NXDOMAIN response with no answer records (control, no weird).
4. Valid RFC 2308 Type 2 NXDOMAIN response with a legitimate CNAME answer record (control, no weird).
5. Standard NOERROR response with an A answer record (control, no weird).

Written with Gemini 3.8 Flash using Scapy.
"""

from pathlib import Path

from scapy.all import DNS, DNSQR, DNSRR, IP, UDP, Ether, wrpcap
from scapy.layers.dns import DNSRRSOA

BASE_TIME = 1_700_000_000.0


def main():
    packets = []

    # Flow 1: NXDOMAIN with disallowed TXT answer record (type 16)
    c1_q = (
        Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")
        / IP(src="192.0.2.10", dst="198.51.100.53")
        / UDP(sport=51001, dport=53)
        / DNS(id=0x1001, qr=0, rd=1, qd=DNSQR(qname="invalid-txt.example.com", qtype="TXT"))
    )
    c1_r = (
        Ether(src="02:00:00:00:00:02", dst="02:00:00:00:00:01")
        / IP(src="198.51.100.53", dst="192.0.2.10")
        / UDP(sport=53, dport=51001)
        / DNS(
            id=0x1001,
            qr=1,
            aa=1,
            rcode=3,
            qd=DNSQR(qname="invalid-txt.example.com", qtype="TXT"),
            an=DNSRR(rrname="invalid-txt.example.com", type="TXT", rdata=["payload"]),
        )
    )
    packets.extend([c1_q, c1_r])

    # Flow 2: NXDOMAIN with disallowed A answer record (type 1)
    c2_q = (
        Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")
        / IP(src="192.0.2.10", dst="198.51.100.53")
        / UDP(sport=51002, dport=53)
        / DNS(id=0x1002, qr=0, rd=1, qd=DNSQR(qname="invalid-a.example.com", qtype="A"))
    )
    c2_r = (
        Ether(src="02:00:00:00:00:02", dst="02:00:00:00:00:01")
        / IP(src="198.51.100.53", dst="192.0.2.10")
        / UDP(sport=53, dport=51002)
        / DNS(
            id=0x1002,
            qr=1,
            aa=1,
            rcode=3,
            qd=DNSQR(qname="invalid-a.example.com", qtype="A"),
            an=DNSRR(rrname="invalid-a.example.com", type="A", rdata="192.0.2.1"),
        )
    )
    packets.extend([c2_q, c2_r])

    # Flow 3: Standard NXDOMAIN response with authority SOA and no answer (control)
    c3_q = (
        Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")
        / IP(src="192.0.2.10", dst="198.51.100.53")
        / UDP(sport=51003, dport=53)
        / DNS(id=0x1003, qr=0, rd=1, qd=DNSQR(qname="nxdomain.example.com", qtype="A"))
    )
    c3_r = (
        Ether(src="02:00:00:00:00:02", dst="02:00:00:00:00:01")
        / IP(src="198.51.100.53", dst="192.0.2.10")
        / UDP(sport=53, dport=51003)
        / DNS(
            id=0x1003,
            qr=1,
            aa=1,
            rcode=3,
            qd=DNSQR(qname="nxdomain.example.com", qtype="A"),
            ns=DNSRRSOA(
                rrname="example.com.",
                mname="ns1.example.com.",
                rname="hostmaster.example.com.",
                serial=1,
                refresh=7200,
                retry=3600,
                expire=1209600,
                minimum=3600,
            ),
        )
    )
    packets.extend([c3_q, c3_r])

    # Flow 4: Legitimate CNAME alias chain in NXDOMAIN response (RFC 2308 Type 2 control)
    c4_q = (
        Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")
        / IP(src="192.0.2.10", dst="198.51.100.53")
        / UDP(sport=51004, dport=53)
        / DNS(id=0x1004, qr=0, rd=1, qd=DNSQR(qname="alias.example.com", qtype="A"))
    )
    c4_r = (
        Ether(src="02:00:00:00:00:02", dst="02:00:00:00:00:01")
        / IP(src="198.51.100.53", dst="192.0.2.10")
        / UDP(sport=53, dport=51004)
        / DNS(
            id=0x1004,
            qr=1,
            aa=1,
            rcode=3,
            qd=DNSQR(qname="alias.example.com", qtype="A"),
            an=DNSRR(rrname="alias.example.com", type="CNAME", rdata="nonexistent.example.com"),
            ns=DNSRRSOA(
                rrname="example.com.",
                mname="ns1.example.com.",
                rname="hostmaster.example.com.",
                serial=1,
                refresh=7200,
                retry=3600,
                expire=1209600,
                minimum=3600,
            ),
        )
    )
    packets.extend([c4_q, c4_r])

    # Flow 5: Standard NOERROR response with terminal A answer (control)
    c5_q = (
        Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")
        / IP(src="192.0.2.10", dst="198.51.100.53")
        / UDP(sport=51005, dport=53)
        / DNS(id=0x1005, qr=0, rd=1, qd=DNSQR(qname="valid.example.com", qtype="A"))
    )
    c5_r = (
        Ether(src="02:00:00:00:00:02", dst="02:00:00:00:00:01")
        / IP(src="198.51.100.53", dst="192.0.2.10")
        / UDP(sport=53, dport=51005)
        / DNS(
            id=0x1005,
            qr=1,
            aa=1,
            rcode=0,
            qd=DNSQR(qname="valid.example.com", qtype="A"),
            an=DNSRR(rrname="valid.example.com", type="A", rdata="192.0.2.100"),
        )
    )
    packets.extend([c5_q, c5_r])

    for index, p in enumerate(packets):
        p.time = BASE_TIME + index * 0.001

    wrpcap(str(Path(__file__).with_suffix("")), packets)


if __name__ == "__main__":
    main()
