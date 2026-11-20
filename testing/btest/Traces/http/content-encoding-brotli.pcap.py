#!/usr/bin/env python3
"""HTTP/1.1 responses using Content-Encoding: br (Brotli).

Three GET requests, each on its own connection. The server's responses carry
a Brotli-compressed HTML body:

  * Port 40000: body sent with a Content-Length header.
  * Port 40001: body sent with Transfer-Encoding: chunked, split into several
    chunks that also span several TCP segments.
  * Port 40002: Content-Length body whose Brotli stream is corrupted
    part-way through, so decompression fails.

The plaintext is large enough to decompress into multiple 4 KiB output
blocks. The response is split into 200 byte TCP segments.

Requires the "brotli" Python module for compression; its output is
deterministic for a fixed quality setting.

Written with claude-opus-5-5 using Scapy (disclose AI assistance per
AI_POLICY.md).
"""

from pathlib import Path

import brotli
from scapy.all import IP, TCP, Ether, Raw, wrpcap

CLIENT = "192.0.2.1"
SERVER = "192.0.2.2"
CLIENT_PORT = 40000
SERVER_PORT = 80
BASE_TIME = 1_700_000_000.0
SEGMENT_SIZE = 200

PLAINTEXT = (
    b"<html><body><h1>Hello from br-encoded HTTP/1.1</h1>\n"
    + b"".join(b"<p>Line %d of a Brotli-compressed body.</p>\n" % i for i in range(400))
    + b"</body></html>\n"
)

COMPRESSED = brotli.compress(PLAINTEXT, quality=11)


def pkt(is_orig, seq, ack, flags, payload=b"", client_port=CLIENT_PORT):
    if is_orig:
        src, dst, sport, dport = CLIENT, SERVER, client_port, SERVER_PORT
        eth_src, eth_dst = "02:00:00:00:00:01", "02:00:00:00:00:02"
    else:
        src, dst, sport, dport = SERVER, CLIENT, SERVER_PORT, client_port
        eth_src, eth_dst = "02:00:00:00:00:02", "02:00:00:00:00:01"
    p = (
        Ether(src=eth_src, dst=eth_dst)
        / IP(src=src, dst=dst)
        / TCP(sport=sport, dport=dport, seq=seq, ack=ack, flags=flags)
    )
    if payload:
        p = p / Raw(payload)
    return p


def chunk_encode(data, size):
    """Encode data as HTTP chunks of the given size plus the terminating chunk."""
    out = b""
    for i in range(0, len(data), size):
        piece = data[i : i + size]
        out += b"%x\r\n%s\r\n" % (len(piece), piece)
    return out + b"0\r\n\r\n"


def build_response(kind):
    if kind == "content-length":
        body = COMPRESSED
        framing = b"Content-Length: %d\r\n" % len(body)
    elif kind == "chunked":
        body = chunk_encode(COMPRESSED, 150)
        framing = b"Transfer-Encoding: chunked\r\n"
    elif kind == "corrupt":
        # Keep the stream header intact, then overwrite the middle with junk.
        mid = len(COMPRESSED) // 2
        body = COMPRESSED[:mid] + b"\xff" * 64 + COMPRESSED[mid + 64 :]
        framing = b"Content-Length: %d\r\n" % len(body)
    else:
        raise ValueError(kind)

    headers = (
        b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Encoding: br\r\n%s\r\n"
    ) % framing
    return headers + body


def build_connection(client_port, kind):
    client_seq, server_seq = 1000, 2000
    packets = [
        pkt(True, client_seq, 0, "S", client_port=client_port),
        pkt(False, server_seq, client_seq + 1, "SA", client_port=client_port),
        pkt(True, client_seq + 1, server_seq + 1, "A", client_port=client_port),
    ]
    client_seq += 1
    server_seq += 1

    request = (
        b"GET /%s HTTP/1.1\r\n"
        b"Host: 192.0.2.2\r\n"
        b"User-Agent: scapy-generator\r\n"
        b"Accept-Encoding: br\r\n"
        b"\r\n"
    ) % kind.encode()
    packets.append(pkt(True, client_seq, server_seq, "PA", request, client_port))
    client_seq += len(request)

    response = build_response(kind)
    for i in range(0, len(response), SEGMENT_SIZE):
        segment = response[i : i + SEGMENT_SIZE]
        packets.append(pkt(False, server_seq, client_seq, "PA", segment, client_port))
        server_seq += len(segment)
        packets.append(pkt(True, client_seq, server_seq, "A", client_port=client_port))

    # Clean FIN/ACK teardown, client-initiated (a FIN consumes one seq).
    packets.append(pkt(True, client_seq, server_seq, "FA", client_port=client_port))
    client_seq += 1
    packets.append(pkt(False, server_seq, client_seq, "FA", client_port=client_port))
    server_seq += 1
    packets.append(pkt(True, client_seq, server_seq, "A", client_port=client_port))
    return packets


def build_packets():
    packets = []
    packets += build_connection(CLIENT_PORT, "content-length")
    packets += build_connection(CLIENT_PORT + 1, "chunked")
    packets += build_connection(CLIENT_PORT + 2, "corrupt")
    return packets


def main():
    packets = build_packets()

    for index, p in enumerate(packets):
        p.time = BASE_TIME + index * 0.001

    wrpcap(str(Path(__file__).with_suffix("")), packets)


if __name__ == "__main__":
    main()
