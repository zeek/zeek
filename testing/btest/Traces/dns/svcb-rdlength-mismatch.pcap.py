#!/usr/bin/env python3
"""
Generate svcb-rdlength-mismatch.pcap with a DNS SVCB response where
RDLENGTH is shorter than the minimum valid SVCB RDATA size.

Adapted by Claude Sonnet 5.5 (Anthropic) to use Scapy's DNS layer, fixed MACs
and timestamps, and to write next to the script.
"""

from pathlib import Path

from scapy.all import DNS, DNSQR, DNSRR, DNSRROPT, IP, UDP, Ether, wrpcap

QNAME = "www.example.com"
TYPE_SVCB = 64
CLIENT_MAC = "02:00:00:00:00:01"
SERVER_MAC = "02:00:00:00:00:02"
BASE_TIME = 1_700_000_000.0


def question():
    return DNSQR(qname=QNAME, qtype=TYPE_SVCB, qclass=1)


def main():
    query = DNS(id=0x1234, rd=1, qd=question())

    response = DNS(
        id=0x1234,
        qr=1,
        rd=1,
        ra=1,
        qd=question(),
        # RDLENGTH=2 is malformed for SVCB (minimum is 3 bytes). The name is a
        # compression pointer to the question at offset 12.
        an=DNSRR(
            rrname=b"\xc0\x0c",
            type=TYPE_SVCB,
            rclass=1,
            ttl=300,
            rdlen=2,
            rdata=b"\x00\x01",
        ),
        # Include an OPT RR so bytes follow the malformed answer in the message.
        ar=DNSRROPT(rrname=b"", rclass=1232, extrcode=0, version=0, z=0, rdlen=0),
    )

    packets = [
        Ether(src=CLIENT_MAC, dst=SERVER_MAC)
        / IP(src="10.0.0.2", dst="10.0.0.1")
        / UDP(sport=1234, dport=53)
        / query,
        Ether(src=SERVER_MAC, dst=CLIENT_MAC)
        / IP(src="10.0.0.1", dst="10.0.0.2")
        / UDP(sport=53, dport=1234)
        / response,
    ]
    for index, pkt in enumerate(packets):
        pkt.time = BASE_TIME + index * 0.001

    wrpcap(str(Path(__file__).with_suffix("")), packets)


if __name__ == "__main__":
    main()
