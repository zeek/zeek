#!/usr/bin/env python3
"""HTTP requests whose bodies use stacked Transfer-Encoding codings.

Two POST requests, each on its own connection, carry a body built from the same
plaintext but with the transfer codings stacked in opposite orders:

  * "gzip,chunked" - gzip-compress the plaintext, then chunk the result. A
    recipient de-chunks first and then gunzips.
  * "chunked,gzip" - chunk the plaintext, then gzip the result. A recipient
    gunzips first and then de-chunks.

The Transfer-Encoding header lists the codings in application order, so the two
requests exercise Zeek's handling of stacked transfer codings in both
directions.

Written with global.anthropic.claude-opus-4-8 using Scapy (disclose AI
assistance per AI_POLICY.md).
"""

import gzip
import io
from pathlib import Path

from scapy.all import IP, TCP, Ether, Raw, wrpcap

CLIENT = "192.0.2.1"
SERVER = "192.0.2.2"
CLIENT_PORT = 40000
SERVER_PORT = 80
BASE_TIME = 1_700_000_000.0

PLAINTEXT = b"Hello, Transfer-Encoding gzip,chunked world!\n"


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


def gzip_bytes(data):
    """Deterministically gzip-compress data (mtime=0 for reproducible bytes)."""
    buf = io.BytesIO()
    with gzip.GzipFile(fileobj=buf, mode="wb", mtime=0) as f:
        f.write(data)
    return buf.getvalue()


def chunk_encode(data):
    """Encode data as a single HTTP chunk followed by the terminating chunk."""
    return b"%x\r\n%s\r\n0\r\n\r\n" % (len(data), data)


def build_request(encoding):
    if encoding == "gzip,chunked":
        # Codings applied in the order listed: gzip then chunked. So compress
        # the plaintext, then chunk the compressed bytes.
        body = chunk_encode(gzip_bytes(PLAINTEXT))
    elif encoding == "chunked,gzip":
        # Reversed order: chunk the plaintext, then gzip the chunked bytes.
        body = gzip_bytes(chunk_encode(PLAINTEXT))
    else:
        raise ValueError(encoding)
    headers = (
        b"POST /upload HTTP/1.1\r\n"
        b"Host: 192.0.2.2\r\n"
        b"User-Agent: scapy-generator\r\n"
        b"Transfer-Encoding: %s\r\n"
        b"\r\n"
    ) % encoding.encode()
    return headers + body


def build_connection(client_port, encoding):
    """Build a full connection carrying a single request with the given coding."""
    client_seq, server_seq = 1000, 2000
    packets = [
        pkt(True, client_seq, 0, "S", client_port=client_port),
        pkt(False, server_seq, client_seq + 1, "SA", client_port=client_port),
        pkt(True, client_seq + 1, server_seq + 1, "A", client_port=client_port),
    ]
    client_seq += 1
    server_seq += 1

    request = build_request(encoding)
    packets.append(pkt(True, client_seq, server_seq, "PA", request, client_port))
    client_seq += len(request)
    packets.append(pkt(False, server_seq, client_seq, "A", client_port=client_port))

    # Clean FIN/ACK teardown, client-initiated (a FIN consumes one seq).
    packets.append(pkt(True, client_seq, server_seq, "FA", client_port=client_port))
    client_seq += 1
    packets.append(pkt(False, server_seq, client_seq, "FA", client_port=client_port))
    server_seq += 1
    packets.append(pkt(True, client_seq, server_seq, "A", client_port=client_port))
    return packets


def build_packets():
    packets = []
    packets += build_connection(CLIENT_PORT, "gzip,chunked")
    packets += build_connection(CLIENT_PORT + 1, "chunked,gzip")
    return packets


def main():
    packets = build_packets()

    for index, p in enumerate(packets):
        p.time = BASE_TIME + index * 0.001

    wrpcap(str(Path(__file__).with_suffix("")), packets)


if __name__ == "__main__":
    main()
