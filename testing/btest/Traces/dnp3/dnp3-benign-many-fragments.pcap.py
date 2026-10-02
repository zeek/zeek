#!/usr/bin/env python3
"""A benign DNP3 connection carrying many small application fragments.

A master repeatedly integrity-polls an outstation over a single TCP
connection: hundreds of small READ requests and their responses, each a
complete single-frame DNP3 application fragment (transport FIR+FIN set). No
single fragment is large, but the connection total in each direction is well
into the kilobytes.

This exercises the DNP3::max_application_layer_fragment_size cap. The cap
measures the *current* application fragment being reassembled in the binpac
flow buffer, which drains after every FIN. A benign long connection like this
one must therefore stay quiet even when the cap is lowered far below the
connection total, as long as it stays above any single fragment. If the cap
ever measured cumulative per-connection bytes instead, this trace would trip
dnp3_max_application_layer_fragment_size_exceeded.

The request and response fragments are the exact, byte-for-byte application
packets from the committed, CI-validated Traces/dnp3/dnp3_read.pcap (a Class
1/2/3/0 integrity poll and its response). Replaying known-good bytes keeps the
frames valid by construction -- CRCs, lengths, and transport framing are
whatever Zeek already parses cleanly -- rather than re-deriving DNP3 framing
here. The payloads are highly repetitive, so the trace is committed gzip'd as
dnp3-benign-many-fragments.pcap.gz. No network I/O is performed.

Written with Claude Opus 4.8 using Scapy; the DNP3 fragment bytes are copied
from the existing dnp3_read.pcap fixture.
"""

import gzip
from pathlib import Path

from scapy.all import IP, TCP, Ether, Raw, wrpcap

CLIENT = "192.0.2.1"
SERVER = "192.0.2.2"
CLIENT_PORT = 40000
SERVER_PORT = 20000  # DNP3
BASE_TIME = 1_700_000_000.0

# One complete DNP3 application fragment each, taken verbatim from
# dnp3_read.pcap (client->server integrity poll, server->client response).
# Each is a single link frame with the transport FIR+FIN bits set, so each is
# an independent application fragment with its own 8-byte pseudo link header.
POLL = bytes.fromhex("056414c4020003004503c7c8013c02063c03063c04063c010642ac")
RESPONSE = bytes.fromhex(
    "05647444030002006854f4c88100000102000008810181010101d374"
    "0101010a02000006000000000000011e6ca40100000e01ef03000001"
    "0300000001ed2178030000012bd1ffff01ed03000001e62e41c90000"
    "01170d0200000000000001b50c02c650000000000000018a0d020000"
    "000000000693000000000000000000000000000000ffff"
)

# A master polling an outstation hundreds of times is a normal long-lived DNP3
# connection. The counts are chosen so the per-direction application-layer
# total (~11 KB request, ~11 KB response) sits well above a lowered test cap,
# while each individual fragment stays tiny (<= ~120 bytes).
POLL_COUNT = 800
RESPONSE_COUNT = 100

TCP_SEGMENT_TARGET = 1460


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


def segments(is_orig, stream, seq, ack):
    """Slice a byte stream into TCP segments, advancing the sender's seq."""
    out = []
    for offset in range(0, len(stream), TCP_SEGMENT_TARGET):
        chunk = stream[offset : offset + TCP_SEGMENT_TARGET]
        out.append(pkt(is_orig, seq, ack, "PA", chunk))
        seq += len(chunk)
    return out, seq


def build_packets():
    client_seq, server_seq = 1000, 2000
    packets = [
        pkt(True, client_seq, 0, "S"),
        pkt(False, server_seq, client_seq + 1, "SA"),
        pkt(True, client_seq + 1, server_seq + 1, "A"),
    ]
    client_seq += 1
    server_seq += 1

    # Master sends many back-to-back integrity polls.
    poll_pkts, client_seq = segments(True, POLL * POLL_COUNT, client_seq, server_seq)
    packets += poll_pkts

    # Outstation acknowledges and answers with many responses.
    packets.append(pkt(False, server_seq, client_seq, "A"))
    resp_pkts, server_seq = segments(
        False, RESPONSE * RESPONSE_COUNT, server_seq, client_seq
    )
    packets += resp_pkts

    # Clean client-initiated teardown. The client has unacknowledged server
    # data, so it clears the backlog with a plain ACK before closing.
    packets.append(pkt(True, client_seq, server_seq, "A"))
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

    with gzip.GzipFile(Path(__file__).with_suffix(".gz"), "wb", mtime=0) as f:
        wrpcap(f, packets)


if __name__ == "__main__":
    main()
