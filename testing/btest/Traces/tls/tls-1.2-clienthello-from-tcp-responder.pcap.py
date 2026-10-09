#!/usr/bin/env python3
"""Generate a TLS 1.2 trace with reversed TCP and TLS application roles.

The TCP responder acts as the TLS client and sends the ClientHello, while the
TCP originator acts as the TLS server and sends the ServerHello. This exercises
TLS DPD when the application roles differ from the TCP roles.

Generated with claude-opus-5-5 to follow the
scapy-pcap generator conventions.
"""

from pathlib import Path

from scapy.all import IP, TCP, Ether, wrpcap
from scapy.layers.tls.handshake import TLSClientHello, TLSServerHello
from scapy.layers.tls.record import TLS

ORIG = "192.0.2.10"
RESP = "192.0.2.20"
ORIG_PORT = 41000
RESP_PORT = 31338  # non-standard port, so only DPD can identify TLS
BASE_TIME = 1_700_000_000.0


def pkt(is_orig, seq, ack, flags, payload=None):
    if is_orig:
        src, dst, sport, dport = ORIG, RESP, ORIG_PORT, RESP_PORT
        eth_src, eth_dst = "02:00:00:00:00:10", "02:00:00:00:00:20"
    else:
        src, dst, sport, dport = RESP, ORIG, RESP_PORT, ORIG_PORT
        eth_src, eth_dst = "02:00:00:00:00:20", "02:00:00:00:00:10"
    p = (
        Ether(src=eth_src, dst=eth_dst)
        / IP(src=src, dst=dst)
        / TCP(sport=sport, dport=dport, seq=seq, ack=ack, flags=flags)
    )
    if payload is not None:
        p = p / payload
    return p


def client_hello():
    return TLS(
        type=22,
        version=0x0301,
        msg=[
            TLSClientHello(
                version=0x0303,
                gmt_unix_time=0x00010203,
                random_bytes=bytes(range(0x04, 0x20)),
                sid=b"",
                ciphers=[0x002F],  # TLS_RSA_WITH_AES_128_CBC_SHA
                comp=[0],
                ext=[],
            )
        ],
    )


def server_hello():
    return TLS(
        type=22,
        version=0x0303,
        msg=[
            TLSServerHello(
                version=0x0303,
                gmt_unix_time=0x20212223,
                random_bytes=bytes(range(0x24, 0x40)),
                sid=b"",
                cipher=0x002F,
                comp=[0],
                ext=[],
            )
        ],
    )


def build_packets():
    orig_seq, resp_seq = 1000, 5000
    packets = [
        pkt(True, orig_seq, 0, "S"),
        pkt(False, resp_seq, orig_seq + 1, "SA"),
        pkt(True, orig_seq + 1, resp_seq + 1, "A"),
    ]
    orig_seq += 1
    resp_seq += 1

    # The TCP responder is the TLS client and sends the ClientHello.
    hello = client_hello()
    packets.append(pkt(False, resp_seq, orig_seq, "PA", hello))
    resp_seq += len(hello)
    packets.append(pkt(True, orig_seq, resp_seq, "A"))

    # The TCP originator is the TLS server and answers with the ServerHello.
    hello = server_hello()
    packets.append(pkt(True, orig_seq, resp_seq, "PA", hello))
    orig_seq += len(hello)
    packets.append(pkt(False, resp_seq, orig_seq, "A"))

    # Clean FIN/ACK teardown, originator-initiated (a FIN consumes one seq).
    packets.append(pkt(True, orig_seq, resp_seq, "FA"))
    orig_seq += 1
    packets.append(pkt(False, resp_seq, orig_seq, "FA"))
    resp_seq += 1
    packets.append(pkt(True, orig_seq, resp_seq, "A"))
    return packets


def main():
    packets = build_packets()

    for index, p in enumerate(packets):
        p.time = BASE_TIME + index * 0.001

    wrpcap(str(Path(__file__).with_suffix("")), packets)


if __name__ == "__main__":
    main()
