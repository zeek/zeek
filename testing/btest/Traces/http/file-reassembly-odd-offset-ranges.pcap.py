#!/usr/bin/env python3
"""HTTP 206 responses whose Content-Range offsets are all odd.

Each 1-byte response delivers a chunk at a non-zero, non-contiguous offset, so
the file reassembler keeps one block per response. The reassembly cap
(File.cc DeliverChunk) counts only payload bytes, not per-block overhead.

Originally an ad-hoc struct-based reproducer, adapted with
Claude Sonnet 5.5 to use Scapy.
"""

from pathlib import Path

from scapy.all import IP, TCP, Ether, Raw, wrpcap

CLIENT = "192.0.2.1"
SERVER = "192.0.2.2"
CLIENT_PORT = 40000
SERVER_PORT = 80
BASE_TIME = 1_700_000_000.0

REQUEST_COUNT = 20

REQUEST = b"GET /f HTTP/1.1\r\nHost: a\r\nRange: bytes=0-9\r\n\r\n"


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


def response(i):
    off = 2 * i + 1  # odd: never offset 0
    return (
        b"HTTP/1.1 206 Partial Content\r\n"
        b"Content-Range: bytes %d-%d/*\r\n"
        b"Content-Length: 1\r\n\r\nX" % (off, off)
    )


def build_packets():
    client_seq, server_seq = 1000, 5000
    packets = [
        pkt(True, client_seq, 0, "S"),
        pkt(False, server_seq, client_seq + 1, "SA"),
        pkt(True, client_seq + 1, server_seq + 1, "A"),
    ]
    client_seq += 1
    server_seq += 1

    # One request per response, no pipelining. The next request acks the
    # previous response.
    for i in range(REQUEST_COUNT):
        packets.append(pkt(True, client_seq, server_seq, "PA", REQUEST))
        client_seq += len(REQUEST)

        resp = response(i)
        packets.append(pkt(False, server_seq, client_seq, "PA", resp))
        server_seq += len(resp)

    # Ack the last response before closing.
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
