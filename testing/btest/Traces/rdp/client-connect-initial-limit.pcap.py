#!/usr/bin/env python3
"""Generate an RDP trace with two client Connect-Initial messages.

The capture completes a handshake and then sends two parser-accepted client
Connect-Initial (``0x65``) messages, each carrying a valid, in-range client
channel vector. Zeek accepts the first Connect-Initial and rejects the second,
exercising the single-Connect-Initial-per-connection enforcement. This
reproducer performs no network I/O.

Generated with Claude Opus 4.8.
"""

import argparse
import struct
from pathlib import Path

from scapy.all import IP, TCP, Ether, Raw, wrpcap

CLIENT_IP = "192.0.2.1"
SERVER_IP = "192.0.2.2"
CLIENT_MAC = "02:00:00:00:00:01"
SERVER_MAC = "02:00:00:00:00:02"
CLIENT_PORT = 40000
SERVER_PORT = 3389
BASE_TS = 1_700_000_000.0
DEFAULT_MESSAGES = 2
DEFAULT_CHANNELS = 1
MIN_MESSAGES = 2
MAX_CHANNELS = 31
WINDOW_SCALE = [("WScale", 8), ("NOP", None)]


def pkt(*, seq, ack, flags, ident, payload=b"", reverse=False, options=None):
    """Build one Ethernet/IPv4/TCP packet; scapy fills in the checksums."""
    if reverse:
        eth = Ether(src=SERVER_MAC, dst=CLIENT_MAC)
        ip = IP(src=SERVER_IP, dst=CLIENT_IP, id=ident, flags="DF", ttl=64)
        tcp = TCP(
            sport=SERVER_PORT,
            dport=CLIENT_PORT,
            seq=seq,
            ack=ack,
            flags=flags,
            window=65535,
        )
    else:
        eth = Ether(src=CLIENT_MAC, dst=SERVER_MAC)
        ip = IP(src=CLIENT_IP, dst=SERVER_IP, id=ident, flags="DF", ttl=64)
        tcp = TCP(
            sport=CLIENT_PORT,
            dport=SERVER_PORT,
            seq=seq,
            ack=ack,
            flags=flags,
            window=65535,
        )
    if options:
        tcp.options = options
    p = eth / ip / tcp
    if payload:
        p = p / Raw(load=payload)
    return p


def tpkt(application_type, header):
    """Wrap one MCS header in COTP and TPKT framing."""
    body = b"\x02\xf0\x80\x7f" + bytes([application_type]) + header
    return b"\x03\x00" + struct.pack("!H", len(body) + 4) + body


def client_header(data_blocks):
    """Wrap data blocks in a minimal GCC client request."""
    asn1_fields = b"\x02\x00\x04\x00\x04\x00\x01\x00" + b"\x30\x00" * 3
    gcc_connection = b"\x00\x00\x00\x00"
    gcc_request = b"\x00\x00\x00\x00\x00\x01\x00\x04Duca\x00\x00"
    client = (
        asn1_fields + b"\x00\x00\x00\x00" + gcc_connection + gcc_request + data_blocks
    )
    return tpkt(0x65, client)


def client_network_message(channel_count):
    """Build a client channel vector."""
    channel = b"CHAN\x00\x00\x00\x00" + struct.pack("<I", 0)
    network = struct.pack("<I", channel_count) + channel * channel_count
    block_length = 4 + len(network)
    block = struct.pack("<HH", 0xC003, block_length) + network
    return client_header(block)


def connection_packets(message_count, channel_count):
    """Yield a handshake and an in-order stream of Connect-Initial messages."""
    client_sequence = 1000
    server_sequence = 5000
    ident = 1
    packets = []

    packets.append(
        pkt(
            seq=client_sequence,
            ack=0,
            flags="S",
            ident=ident,
            options=WINDOW_SCALE,
        )
    )
    packets.append(
        pkt(
            seq=server_sequence,
            ack=client_sequence + 1,
            flags="SA",
            ident=ident + 1,
            reverse=True,
            options=WINDOW_SCALE,
        )
    )
    packets.append(
        pkt(
            seq=client_sequence + 1,
            ack=server_sequence + 1,
            flags="A",
            ident=ident + 2,
        )
    )

    stream = client_network_message(channel_count) * message_count
    packets.append(
        pkt(
            seq=client_sequence + 1,
            ack=server_sequence + 1,
            flags="PA",
            ident=ident + 3,
            payload=stream,
        )
    )
    packets.append(
        pkt(
            seq=server_sequence + 1,
            ack=client_sequence + 1 + len(stream),
            flags="A",
            ident=ident + 4,
            reverse=True,
        )
    )

    return packets


def main():
    """Parse command-line arguments and generate the capture."""
    default_output = Path(__file__).with_suffix("")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", nargs="?", type=Path, default=default_output)
    parser.add_argument("--messages", type=int, default=DEFAULT_MESSAGES)
    parser.add_argument("--channels", type=int, default=DEFAULT_CHANNELS)
    args = parser.parse_args()
    if args.messages < MIN_MESSAGES:
        parser.error(
            f"--messages must be at least {MIN_MESSAGES} to send a second Connect-Initial"
        )
    if not 1 <= args.channels <= MAX_CHANNELS:
        parser.error(f"--channels must be between 1 and {MAX_CHANNELS}")

    packets = connection_packets(args.messages, args.channels)
    for index, packet in enumerate(packets):
        packet.time = BASE_TS + index * 0.001
    wrpcap(str(args.output), packets)
    print(f"Wrote {len(packets)} packets to {args.output}")


if __name__ == "__main__":
    main()
