#!/usr/bin/env python3
"""
Generate connect-prefix-match.pcap: an HTTP request whose method is a prefix
of "CONNECT".

The bug: HTTP_Analyzer::HTTP_Request() used
strncasecmp(method, "CONNECT", method_len) to detect CONNECT requests. Because
the comparison length was the (short) request method's length, any method that
is a prefix of "CONNECT" — e.g. "CON" — matched. Zeek then treated the
connection as a CONNECT tunnel and stopped analyzing the HTTP inside it,
letting a following "FETCH /secret" request and a bogus response body evade
analysis. The fix also requires method_len == 7 (len("CONNECT")).

Generated with Claude Opus 4.8 (Anthropic), adapted with Claude Sonnet 5.5
(Anthropic) to follow the scapy-pcap conventions (fixed packet timestamps).
"""

from pathlib import Path

from scapy.all import IP, TCP, Ether, Raw, wrpcap

CLIENT = "10.0.0.1"
SERVER = "10.0.0.2"
CLIENT_PORT = 45678
SERVER_PORT = 80
BASE_TIME = 1_700_000_000.0

METHOD = "CON"  # a prefix of "CONNECT"


def pkt(is_orig, seq, ack, flags, payload=b""):
    if is_orig:
        src, dst, sport, dport = CLIENT, SERVER, CLIENT_PORT, SERVER_PORT
        eth_src, eth_dst = "00:00:00:00:00:01", "00:00:00:00:00:02"
    else:
        src, dst, sport, dport = SERVER, CLIENT, SERVER_PORT, CLIENT_PORT
        eth_src, eth_dst = "00:00:00:00:00:02", "00:00:00:00:00:01"
    p = (
        Ether(src=eth_src, dst=eth_dst)
        / IP(src=src, dst=dst)
        / TCP(sport=sport, dport=dport, seq=seq, ack=ack, flags=flags)
    )
    if payload:
        p = p / Raw(payload)
    return p


def build_packets():
    connect_request = (METHOD + " host:443 HTTP/1.1\r\nHost: a\r\n\r\n").encode()
    connect_reply = b"HTTP/1.1 200 OK\r\n\r\n"
    tunneled_request = b"FETCH /secret HTTP/1.1\r\nHost: evil.example\r\n\r\n"
    tunneled_reply = b"PWND-4-bytes-of-not-a-status-line"

    c_seq = 1000
    s_seq = 5000

    packets = []

    # Three-way handshake
    packets.append(pkt(True, c_seq, 0, "S"))
    c_seq += 1
    packets.append(pkt(False, s_seq, c_seq, "SA"))
    s_seq += 1
    packets.append(pkt(True, c_seq, s_seq, "A"))

    # Prefix-of-CONNECT request and its reply
    packets.append(pkt(True, c_seq, s_seq, "PA", connect_request))
    c_seq += len(connect_request)
    packets.append(pkt(False, s_seq, c_seq, "PA", connect_reply))
    s_seq += len(connect_reply)
    packets.append(pkt(True, c_seq, s_seq, "A"))

    # Request/response that must still be analyzed (not tunneled away)
    packets.append(pkt(True, c_seq, s_seq, "PA", tunneled_request))
    c_seq += len(tunneled_request)
    packets.append(pkt(False, s_seq, c_seq, "PA", tunneled_reply))
    s_seq += len(tunneled_reply)
    packets.append(pkt(True, c_seq, s_seq, "A"))

    # Teardown
    packets.append(pkt(True, c_seq, s_seq, "FA"))
    c_seq += 1
    packets.append(pkt(False, s_seq, c_seq, "FA"))
    s_seq += 1
    packets.append(pkt(True, c_seq, s_seq, "A"))

    return packets


def main():
    packets = build_packets()

    for index, p in enumerate(packets):
        p.time = BASE_TIME + index * 0.001

    wrpcap(str(Path(__file__).with_suffix("")), packets)


if __name__ == "__main__":
    main()
