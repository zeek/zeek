#!/usr/bin/env python3
"""Generate a DHCP capture for checking bad-cookie option-state handling.

All packets share one Zeek UDP connection. The first packet has the DHCP magic
cookie and a DHCP message type option. The middle packets use an invalid cookie
while carrying pad options followed by a DHCP message type option and end
marker. The final packet again has the DHCP magic cookie and a DHCP message
type option.

The packet sequence is used by a regression test that keeps the DHCP analyzer
attached after violations so retained state can be observed on the final valid
packet.

Generated with Claude Opus 4.8.
"""

from __future__ import annotations

import argparse
from pathlib import Path

from scapy.all import BOOTP, IP, UDP, Ether, Raw, wrpcap

DHCP_COOKIE = b"\x63\x82\x53\x63"
BAD_COOKIE = b"\x00\x00\x00\x00"
# A DHCP message-type option (53) followed by the end marker (255).
MSG_TYPE_AND_END = b"\x35\x01\x01\xff"


def dhcp_packet(xid, options_payload, ts, cookie=DHCP_COOKIE):
    """Build a broadcast DHCP frame with a raw options payload."""
    bootp = BOOTP(
        op=1,
        htype=1,
        hlen=6,
        hops=0,
        xid=xid,
        flags=0x8000,
        chaddr=b"\x00\x11\x22\x33\x44\x55",
    )
    pkt = (
        Ether(src="00:11:22:33:44:55", dst="ff:ff:ff:ff:ff:ff")
        / IP(src="0.0.0.0", dst="255.255.255.255")
        / UDP(sport=68, dport=67)
        / bootp
        / Raw(load=cookie + options_payload)
    )
    pkt.time = ts
    return pkt


def build_packets(bad_count, pad_options):
    """Return good / bad... / good sequence sharing one flow."""
    pads = b"\x00" * pad_options
    packets = []
    ts = 1700000000.0

    # Valid message confirms the analyzer.
    packets.append(dhcp_packet(0x1000, MSG_TYPE_AND_END, ts))

    # Bad-cookie messages carrying pad options. On a vulnerable build each one
    # leaks its parsed options into the flow's retained option vector.
    for i in range(bad_count):
        ts += 0.001
        packets.append(
            dhcp_packet(0x2000 + i, pads + MSG_TYPE_AND_END, ts, cookie=BAD_COOKIE)
        )

    # Final valid message: its emitted option vector reveals any retained state.
    ts += 0.001
    packets.append(dhcp_packet(0x3000, MSG_TYPE_AND_END, ts))

    return packets


def parse_args():
    default_output = Path(__file__).with_suffix("")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=default_output)
    parser.add_argument(
        "--bad-count",
        type=int,
        default=3,
        help="number of bad-cookie messages between the valid ones",
    )
    parser.add_argument(
        "--pad-options",
        type=int,
        default=4,
        help="pad options carried by each bad-cookie message",
    )
    return parser.parse_args()


def main():
    args = parse_args()
    packets = build_packets(args.bad_count, args.pad_options)
    wrpcap(str(args.output), packets)
    print(args.output)


if __name__ == "__main__":
    main()
