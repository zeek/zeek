#!/usr/bin/env python3
"""HTTP responses that hide a binary body behind their Content-Type.

One keep-alive connection carries four GET requests. The first three responses
all return an identical PE-like body (GH-1799):

  * application/octet-stream with Content-Length (control),
  * message/rfc822 with Content-Length,
  * multipart/mixed with a boundary that never occurs in the body.

MIME parsing consumes the message/* body up to its first empty line as inner
headers, and discards a multipart body before its first boundary as preamble,
so neither reaches file analysis in full. The body contains lone CR and LF
bytes, which must survive line-based delivery.

The fourth response is a well-formed multipart/mixed body with one part that
carries the same PE-like content.

Written with claude-opus-5-5 using Scapy (disclose AI assistance per
AI_POLICY.md).
"""

from pathlib import Path

from scapy.all import IP, TCP, Ether, Raw, wrpcap

CLIENT = "192.0.2.1"
SERVER = "192.0.2.2"
CLIENT_PORT = 40000
SERVER_PORT = 80
BASE_TIME = 1_700_000_000.0

# A DOS stub followed by a PE signature and every byte value, mirroring the
# executable from GH-1799.
BODY = (
    b"MZ\x90\x00\x03\x00\x00\x00"
    + b"\x00" * 8
    + b"This program cannot be run in DOS mode.\r\r\n$"
    + b"\x00" * 7
    + b"PE\x00\x00"
    + bytes(range(256))
    + b"\r\n"
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


def request(path):
    return b"GET %s HTTP/1.1\r\nHost: 192.0.2.2\r\n\r\n" % path


MULTIPART_BODY = (
    b"--b\r\nContent-Type: application/octet-stream\r\n\r\n%s\r\n--b--\r\n" % BODY
)


def response(content_type, payload):
    return b"HTTP/1.1 200 OK\r\nContent-Type: %s\r\nContent-Length: %d\r\n\r\n%s" % (
        content_type,
        len(payload),
        payload,
    )


EXCHANGES = [
    (b"/control.exe", b"application/octet-stream", BODY),
    (b"/message.exe", b"message/rfc822", BODY),
    (b"/multipart.exe", b"multipart/mixed; boundary=b", BODY),
    (b"/multipart-part.exe", b"multipart/mixed; boundary=b", MULTIPART_BODY),
]


def build_packets():
    client_seq, server_seq = 1000, 2000
    packets = [
        pkt(True, client_seq, 0, "S"),
        pkt(False, server_seq, client_seq + 1, "SA"),
        pkt(True, client_seq + 1, server_seq + 1, "A"),
    ]
    client_seq += 1
    server_seq += 1

    for path, content_type, payload in EXCHANGES:
        req = request(path)
        packets.append(pkt(True, client_seq, server_seq, "PA", req))
        client_seq += len(req)
        resp = response(content_type, payload)
        packets.append(pkt(False, server_seq, client_seq, "PA", resp))
        server_seq += len(resp)
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
