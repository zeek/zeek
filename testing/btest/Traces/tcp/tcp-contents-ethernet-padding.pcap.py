#!/usr/bin/env python3
"""TCP flow with small, Ethernet-padded segments for set_contents_file().

Every frame is padded to the 60-byte Ethernet minimum, so the captured bytes
of each short data segment extend past the TCP payload. Content extraction
must write only the payload and never the padding, notably for the last
segment of each direction where no later segment overwrites stray bytes.
The padding uses "p" rather than zeros so leaked bytes are visible.

Written with Claude Opus 5.5 using Scapy.
"""

from pathlib import Path

from scapy.all import IP, TCP, Ether, Padding, Raw, wrpcap

CLIENT = "192.0.2.1"
SERVER = "192.0.2.2"
CLIENT_PORT = 31337
SERVER_PORT = 40000
BASE_TIME = 1_700_000_000.0

ETHERNET_MIN_FRAME_LEN = 60  # without FCS

CLIENT_PAYLOADS = [b"A", b"BC", b"D"]
SERVER_PAYLOADS = [b"x", b"yz"]


def pkt(is_orig, seq, ack, flags, payload=b""):
    if is_orig:
        src, dst, sport, dport = CLIENT, SERVER, CLIENT_PORT, SERVER_PORT
        eth_src, eth_dst = "02:00:00:00:00:01", "02:00:00:00:00:02"
    else:
        src, dst, sport, dport = SERVER, CLIENT, SERVER_PORT, CLIENT_PORT
        eth_src, eth_dst = "02:00:00:00:00:02", "02:00:00:00:00:01"
    p = (
        Ether(src=eth_src, dst=eth_dst)
        / IP(src=src, dst=dst)
        / TCP(sport=sport, dport=dport, seq=seq, ack=ack, flags=flags)
    )
    if payload:
        p = p / Raw(payload)
    pad_len = ETHERNET_MIN_FRAME_LEN - len(p)
    if pad_len > 0:
        p = p / Padding(b"p" * pad_len)
    return p


def build_packets():
    client_seq, server_seq = 1000, 2000
    packets = [
        pkt(True, client_seq, 0, "S"),
        pkt(False, server_seq, client_seq + 1, "SA"),
        pkt(True, client_seq + 1, server_seq + 1, "A"),
    ]
    client_seq += 1
    server_seq += 1

    for payload in CLIENT_PAYLOADS:
        packets.append(pkt(True, client_seq, server_seq, "PA", payload))
        client_seq += len(payload)
        packets.append(pkt(False, server_seq, client_seq, "A"))

    for payload in SERVER_PAYLOADS:
        packets.append(pkt(False, server_seq, client_seq, "PA", payload))
        server_seq += len(payload)
        packets.append(pkt(True, client_seq, server_seq, "A"))

    # Clean FIN/ACK teardown, client-initiated (a FIN consumes one seq).
    packets.append(pkt(True, client_seq, server_seq, "FA"))
    client_seq += 1
    packets.append(pkt(False, server_seq, client_seq, "FA"))
    server_seq += 1
    packets.append(pkt(True, client_seq, server_seq, "A"))
    return packets


def main():
    packets = build_packets()

    for index, p in enumerate(packets):
        p.time = BASE_TIME + index * 0.001

    wrpcap(str(Path(__file__).with_suffix("")), packets)


if __name__ == "__main__":
    main()
