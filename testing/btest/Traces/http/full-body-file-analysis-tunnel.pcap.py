#!/usr/bin/env python3
"""A range request repeated inside a CONNECT tunnel on the same connection.

One connection carries a GET with a Range header and its 206 response, then a
CONNECT and its 200 response, and then the same GET and a 206 response with a
different body inside the tunnel. Zeek analyzes the tunnel with a second HTTP
analyzer on the same connection. Both 206 responses share the entity file
handle, which is derived from the URL for range requests, but each must get
its own full body file.

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


RANGE_REQUEST = b"GET /a HTTP/1.1\r\nHost: example.com\r\nRange: bytes=0-9\r\n\r\n"


def partial(body):
    return (
        b"HTTP/1.1 206 Partial Content\r\nContent-Range: bytes 0-9/100\r\n"
        b"Content-Length: %d\r\n\r\n%s" % (len(body), body)
    )


EXCHANGES = [
    (RANGE_REQUEST, partial(b"AAAAAAAAAA")),
    (
        b"CONNECT example.com:80 HTTP/1.1\r\nHost: example.com:80\r\n\r\n",
        b"HTTP/1.1 200 OK\r\n\r\n",
    ),
    (RANGE_REQUEST, partial(b"BBBBBBBBBB")),
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

    for req, resp in EXCHANGES:
        packets.append(pkt(True, client_seq, server_seq, "PA", req))
        client_seq += len(req)
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
