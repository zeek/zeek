#!/usr/bin/env python3
from pathlib import Path

from scapy.all import IP, TCP, wrpcap

CLI, SRV = "10.0.0.1", "10.0.0.2"
SPORT, DPORT = 40000, 21

IAC, SB, SE = 0xFF, 0xFA, 0xF0
AUTH_OPT = 0x25  # 37 = AUTHENTICATION
AUTH_STATUS = 0x02
AUTH_ACCEPT = 0x02

STATUS_ACCEPT = bytes([IAC, SB, AUTH_OPT, AUTH_STATUS, AUTH_ACCEPT, IAC, SE])


def build():
    pkts = []
    seq_c, seq_s = 1000, 5000

    def pkt(src_is_cli, flags, payload=b""):
        nonlocal seq_c, seq_s
        if src_is_cli:
            p = IP(src=CLI, dst=SRV) / TCP(
                sport=SPORT,
                dport=DPORT,
                flags=flags,
                seq=seq_c,
                ack=seq_s if "A" in flags else 0,
            )
            seq_c += len(payload) + (1 if "S" in flags or "F" in flags else 0)
        else:
            p = IP(src=SRV, dst=CLI) / TCP(
                sport=DPORT,
                dport=SPORT,
                flags=flags,
                seq=seq_s,
                ack=seq_c if "A" in flags else 0,
            )
            seq_s += len(payload) + (1 if "S" in flags or "F" in flags else 0)
        if payload:
            p = p / payload
        pkts.append(p)

    pkt(True, "S")
    pkt(False, "SA")
    pkt(True, "A")
    pkt(False, "PA", STATUS_ACCEPT)  # responder STATUS/ACCEPT without prior name
    pkt(True, "A")
    pkt(True, "FA")
    pkt(False, "FA")
    pkt(True, "A")

    return pkts


if __name__ == "__main__":
    outfile = Path(__file__).with_suffix("")
    pkts = build()
    wrpcap(str(outfile), pkts)
