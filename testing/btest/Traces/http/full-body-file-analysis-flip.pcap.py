#!/usr/bin/env python3
"""A multipart response on a connection whose roles Zeek flips.

The capture starts with the server's SYN-ACK. As in http/zeek-image-1080-80-x
(GH-3789), the client uses port 1080 and the server port 80, both likely
server ports, so Zeek attaches the HTTP analyzer before it flips the roles on
the next packet. The single response is multipart/mixed with Content-Length
and a PE-like body before its only boundary, so its full body file is
forwarded from the raw stream.

Written with claude-opus-5-5 using Scapy (disclose AI assistance per
AI_POLICY.md).
"""

from pathlib import Path

from scapy.all import IP, TCP, Ether, Raw, wrpcap

CLIENT = "192.0.2.1"
SERVER = "192.0.2.2"
CLIENT_PORT = 1080
SERVER_PORT = 80
BASE_TIME = 1_700_000_000.0

BODY = b"MZ\x90\x00" + b"\x00" * 60 + b"PE\x00\x00\r\n--b--\r\n"

REQUEST = b"GET /a HTTP/1.1\r\nHost: example.com\r\n\r\n"
RESPONSE = (
    b"HTTP/1.1 200 OK\r\nContent-Type: multipart/mixed; boundary=b\r\n"
    b"Content-Length: %d\r\n\r\n%s" % (len(BODY), BODY)
)


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
    return p


def build_packets():
    # The client's SYN is missing from the capture.
    client_seq, server_seq = 1001, 2001
    return [
        pkt(False, server_seq - 1, client_seq, "SA"),
        pkt(True, client_seq, server_seq, "A"),
        pkt(True, client_seq, server_seq, "PA", REQUEST),
        pkt(False, server_seq, client_seq + len(REQUEST), "PA", RESPONSE),
        pkt(True, client_seq + len(REQUEST), server_seq + len(RESPONSE), "A"),
        pkt(True, client_seq + len(REQUEST), server_seq + len(RESPONSE), "FA"),
        pkt(False, server_seq + len(RESPONSE), client_seq + len(REQUEST) + 1, "FA"),
        pkt(True, client_seq + len(REQUEST) + 1, server_seq + len(RESPONSE) + 1, "A"),
    ]


def main():
    packets = build_packets()

    for index, p in enumerate(packets):
        p.time = BASE_TIME + index * 0.001

    wrpcap(str(Path(__file__).with_suffix("")), packets)


if __name__ == "__main__":
    main()
