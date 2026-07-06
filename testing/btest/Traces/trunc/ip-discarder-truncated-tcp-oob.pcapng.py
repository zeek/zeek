#!/usr/bin/env python3

"""Generate the truncated IPv4/TCP pcapng used for the IP discarder crash path.

The packet's wire length is Ethernet + IPv4 + TCP (54 bytes), but the capture
contains only Ethernet + IPv4 (34 bytes).  This lets Zeek see an IP total length
that includes a TCP header while the captured data stops at the IP payload.
"""

import argparse
from pathlib import Path

from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether
from scapy.utils import PcapNgWriter

DEFAULT_OUTPUT = Path(__file__).with_name("ip-discarder-truncated-tcp-oob.pcapng")


def write_capture(path: Path) -> None:
    pkt = (
        Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")
        / IP(src="10.0.0.1", dst="10.0.0.2", id=0x1001, ttl=64)
        / TCP(sport=12345, dport=80, flags="S", window=8192)
    )

    full_packet = bytes(pkt)
    captured_packet = full_packet[: len(Ether() / IP())]

    assert len(full_packet) == 54
    assert len(captured_packet) == 34

    writer = PcapNgWriter(str(path))
    writer.linktype = 1

    try:
        writer._write_header(captured_packet)
        writer.write_packet(
            captured_packet,
            sec=0.000001,
            caplen=len(captured_packet),
            wirelen=len(full_packet),
        )
    finally:
        writer.close()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "output",
        nargs="?",
        type=Path,
        default=DEFAULT_OUTPUT,
        help=f"output pcapng path (default: {DEFAULT_OUTPUT})",
    )

    args = parser.parse_args()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    write_capture(args.output)
    print(args.output)


if __name__ == "__main__":
    main()
