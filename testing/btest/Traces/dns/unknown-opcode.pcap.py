#!/usr/bin/env python3
"""Generate a reserved DNS opcode and an ordinary query on separate flows.

Written with OpenAI Codex (GPT-6) using Scapy.
"""

from pathlib import Path

from scapy.all import DNS, DNSQR, IP, UDP, Ether, wrpcap

BASE_TIME = 1_700_000_000.0


def main():
    packets = [
        Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")
        / IP(src="192.0.2.1", dst="192.0.2.53")
        / UDP(sport=53000 + index, dport=53)
        / DNS(id=index + 1, opcode=opcode, rd=1, qd=DNSQR(qname="example.test"))
        for index, opcode in enumerate((15, 0))
    ]

    for index, packet in enumerate(packets):
        packet.time = BASE_TIME + index * 0.001

    wrpcap(str(Path(__file__).with_suffix("")), packets)


if __name__ == "__main__":
    main()
