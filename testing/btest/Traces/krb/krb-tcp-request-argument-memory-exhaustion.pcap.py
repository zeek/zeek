#!/usr/bin/env python3
"""
Generate Kerberos/TCP PCAPs that exercise the request-argument validation
added to constrain AS-REQ parsing.

Produces three TCP sessions in a single PCAP:

1. An AS-REQ whose body contains a context tag with index 15 (> 11),
   triggering "invalid unknown Kerberos request argument".

2. An AS-REQ whose body contains two arguments with the same index (5),
   triggering "invalid duplicate Kerberos request argument".

3. A well-formed AS-REQ with a minimal but complete set of standard
   arguments (options, realm, till, nonce, etype) that parses cleanly.

Generated with Claude Opus 4.6.
"""

import argparse
import struct
from pathlib import Path

from scapy.all import IP, TCP, Ether, Raw, wrpcap

CLIENT_IP = "192.0.2.1"
SERVER_IP = "192.0.2.2"
CLIENT_MAC = "02:00:00:00:00:01"
SERVER_MAC = "02:00:00:00:00:02"
SERVER_PORT = 88
TCP_SEGMENT_SIZE = 1400


def ber_length(size):
    if size < 0x80:
        return bytes([size])
    encoded = size.to_bytes((size.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(encoded)]) + encoded


def ber_tlv(tag, value):
    return bytes([tag]) + ber_length(len(value)) + value


def context_tag(index, value):
    """Wrap value in an ASN.1 context-specific constructed tag [index]."""
    return ber_tlv(0xA0 | index, value)


def asn1_integer(val):
    """Encode a small non-negative integer as ASN.1 INTEGER."""
    if val == 0:
        payload = b"\x00"
    else:
        payload = val.to_bytes((val.bit_length() + 8) // 8, "big")
    return ber_tlv(0x02, payload)


def asn1_bitstring(data):
    return ber_tlv(0x03, b"\x00" + data)


def asn1_generalized_time(time_str):
    return ber_tlv(0x18, time_str.encode())


def asn1_sequence(contents):
    return ber_tlv(0x30, contents)


def asn1_octet_string(data):
    return ber_tlv(0x04, data)


def wrap_as_req(body_args_bytes):
    """Wrap body arguments into a full AS-REQ with TCP length prefix."""
    body = context_tag(4, asn1_sequence(body_args_bytes))
    version = context_tag(1, asn1_integer(5))
    msg_type = context_tag(2, asn1_integer(10))  # AS-REQ
    req_body = asn1_sequence(version + msg_type + body)
    # Application tag 10 (AS-REQ) = 0x6A
    as_req = ber_tlv(0x6A, req_body)
    return struct.pack("!I", len(as_req)) + as_req


def make_invalid_index_as_req():
    """AS-REQ with a body argument at context index 15, which is > 11."""
    arg = context_tag(15, asn1_octet_string(b"\x00"))
    return wrap_as_req(arg)


def make_duplicate_index_as_req():
    """AS-REQ with two body arguments both at context index 5 (till)."""
    till1 = context_tag(5, asn1_generalized_time("20370101000000Z"))
    till2 = context_tag(5, asn1_generalized_time("20380101000000Z"))
    return wrap_as_req(till1 + till2)


def make_valid_as_req():
    """A well-formed AS-REQ with options, realm, till, nonce, and etype."""
    options = context_tag(0, asn1_bitstring(b"\x40\x81\x00\x10"))
    realm = context_tag(2, asn1_octet_string(b"EXAMPLE.COM"))
    till = context_tag(5, asn1_generalized_time("20370913024805Z"))
    nonce = context_tag(7, asn1_integer(12345678))
    etype = context_tag(8, asn1_sequence(asn1_integer(17) + asn1_integer(18)))
    return wrap_as_req(options + realm + till + nonce + etype)


def build_tcp_session(client_port, request_payload):
    """Build a full TCP handshake + data + teardown carrying one KRB request."""
    eth_c = Ether(src=CLIENT_MAC, dst=SERVER_MAC)
    eth_s = Ether(src=SERVER_MAC, dst=CLIENT_MAC)

    cseq = 1000
    sseq = 2000
    ip_c = IP(src=CLIENT_IP, dst=SERVER_IP)
    ip_s = IP(src=SERVER_IP, dst=CLIENT_IP)

    packets = [
        eth_c / ip_c / TCP(sport=client_port, dport=SERVER_PORT, flags="S", seq=cseq),
        eth_s
        / ip_s
        / TCP(sport=SERVER_PORT, dport=client_port, flags="SA", seq=sseq, ack=cseq + 1),
        eth_c
        / ip_c
        / TCP(
            sport=client_port, dport=SERVER_PORT, flags="A", seq=cseq + 1, ack=sseq + 1
        ),
    ]
    cseq += 1
    sseq += 1

    for offset in range(0, len(request_payload), TCP_SEGMENT_SIZE):
        chunk = request_payload[offset : offset + TCP_SEGMENT_SIZE]
        packets.append(
            eth_c
            / ip_c
            / TCP(sport=client_port, dport=SERVER_PORT, flags="PA", seq=cseq, ack=sseq)
            / Raw(load=chunk)
        )
        cseq += len(chunk)

    packets.append(
        eth_c
        / ip_c
        / TCP(sport=client_port, dport=SERVER_PORT, flags="FA", seq=cseq, ack=sseq)
    )
    packets.append(
        eth_s
        / ip_s
        / TCP(sport=SERVER_PORT, dport=client_port, flags="FA", seq=sseq, ack=cseq + 1)
    )
    packets.append(
        eth_c
        / ip_c
        / TCP(
            sport=client_port, dport=SERVER_PORT, flags="A", seq=cseq + 1, ack=sseq + 1
        )
    )

    return packets


def main():
    default_output = Path(__file__).with_suffix("")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=default_output)
    args = parser.parse_args()

    packets = []
    packets += build_tcp_session(40000, make_invalid_index_as_req())
    packets += build_tcp_session(40001, make_duplicate_index_as_req())
    packets += build_tcp_session(40002, make_valid_as_req())

    wrpcap(str(args.output), packets)
    print(f"Wrote {len(packets)} packets to {args.output}")


if __name__ == "__main__":
    main()
