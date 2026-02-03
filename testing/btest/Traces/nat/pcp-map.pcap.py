#!/usr/bin/env python3
"""Generates PCP (RFC 6887) TCP MAP requests with a successful, a failed, and
a delayed response.

A client asks its gateway to map a fixed internal TCP port to a fixed external
port, and the gateway grants the mapping with the requested lifetime. The
client then asks for a second mapping, which the gateway refuses with a
non-zero result code. Finally, the client asks for a third mapping, and the
gateway only answers 45 seconds later, which is past Zeek's default NAT
request timeout.

Written with claude-opus-5-5 using Scapy.
"""

from pathlib import Path

from scapy.all import (
    IP,
    UDP,
    BitField,
    ByteField,
    Ether,
    IntField,
    IP6Field,
    Packet,
    ShortField,
    StrFixedLenField,
    X3BytesField,
    wrpcap,
)

CLIENT = "192.168.1.100"
GATEWAY = "192.168.1.1"
EXTERNAL = "203.0.113.5"
CLIENT_PORT = 54321
PCP_PORT = 5351
CLIENT_MAC = "02:00:00:00:00:01"
GATEWAY_MAC = "02:00:00:00:00:02"

# PCP carries IPv4 addresses as IPv4-mapped IPv6 addresses (RFC 6887, 5).
CLIENT_MAPPED = "::ffff:" + CLIENT
EXTERNAL_MAPPED = "::ffff:" + EXTERNAL
ANY_IPV4_MAPPED = "::ffff:0.0.0.0"  # No external address preference.

INTERNAL_PORT = 8080
EXTERNAL_PORT = 18080
LIFETIME = 3600
EPOCH = 1234  # Gateway's seconds since start of epoch.

REFUSED_INTERNAL_PORT = 22
REFUSED_EXTERNAL_PORT = 2222
ERROR_LIFETIME = 1800  # Long lifetime error (RFC 6887, 7.4).

DELAYED_INTERNAL_PORT = 443
DELAYED_EXTERNAL_PORT = 8443
RESPONSE_DELAY = 0.001
LATE_RESPONSE_DELAY = 45.0  # Longer than NAT::request_timeout (30 secs).

# Fixed nonces keep the output reproducible; each mapping uses its own.
SUCCESS_NONCE = bytes.fromhex("0102030405060708090a0b0c")
REFUSED_NONCE = bytes.fromhex("1112131415161718191a1b1c")
DELAYED_NONCE = bytes.fromhex("2122232425262728292a2b2c")

PCP_VERSION = 2
OPCODE_MAP = 1
PROTO_TCP = 6
RESULT_SUCCESS = 0
RESULT_NOT_AUTHORIZED = 2

BASE_TIME = 1_700_000_000.0


def map_fields():
    """MAP opcode-specific fields, shared by requests and responses."""
    return [
        StrFixedLenField("nonce", b"\x00" * 12, 12),
        ByteField("protocol", PROTO_TCP),
        X3BytesField("reserved_map", 0),
        ShortField("internal_port", 0),
        ShortField("external_port", 0),
        IP6Field("external_addr", ANY_IPV4_MAPPED),
    ]


class PCPMapRequest(Packet):
    name = "PCP Map Request"
    fields_desc = [
        ByteField("version", PCP_VERSION),
        BitField("response", 0, 1),
        BitField("opcode", OPCODE_MAP, 7),
        ShortField("reserved", 0),
        IntField("lifetime", 0),
        IP6Field("client_addr", CLIENT_MAPPED),
        *map_fields(),
    ]


class PCPMapResponse(Packet):
    name = "PCP Map Response"
    fields_desc = [
        ByteField("version", PCP_VERSION),
        BitField("response", 1, 1),
        BitField("opcode", OPCODE_MAP, 7),
        ByteField("reserved", 0),
        ByteField("result_code", RESULT_SUCCESS),
        IntField("lifetime", 0),
        IntField("epoch", 0),
        StrFixedLenField("reserved_resp", b"\x00" * 12, 12),
        *map_fields(),
    ]


def build_map_exchange(start, request_fields, response_fields, delay=RESPONSE_DELAY):
    request = (
        Ether(src=CLIENT_MAC, dst=GATEWAY_MAC)
        / IP(src=CLIENT, dst=GATEWAY)
        / UDP(sport=CLIENT_PORT, dport=PCP_PORT)
        / PCPMapRequest(**request_fields)
    )
    response = (
        Ether(src=GATEWAY_MAC, dst=CLIENT_MAC)
        / IP(src=GATEWAY, dst=CLIENT)
        / UDP(sport=PCP_PORT, dport=CLIENT_PORT)
        / PCPMapResponse(**response_fields)
    )
    request.time = start
    response.time = start + delay
    return [request, response]


def build_packets():
    success = build_map_exchange(
        BASE_TIME,
        {
            "lifetime": LIFETIME,
            "nonce": SUCCESS_NONCE,
            "internal_port": INTERNAL_PORT,
            "external_port": EXTERNAL_PORT,
        },
        {
            "lifetime": LIFETIME,
            "epoch": EPOCH,
            "nonce": SUCCESS_NONCE,
            "internal_port": INTERNAL_PORT,
            "external_port": EXTERNAL_PORT,
            "external_addr": EXTERNAL_MAPPED,
        },
    )
    # On failure the gateway copies the MAP fields from the request
    # (RFC 6887, 7.2), and the lifetime says how long the error is valid.
    failure = build_map_exchange(
        BASE_TIME + 0.002,
        {
            "lifetime": LIFETIME,
            "nonce": REFUSED_NONCE,
            "internal_port": REFUSED_INTERNAL_PORT,
            "external_port": REFUSED_EXTERNAL_PORT,
        },
        {
            "result_code": RESULT_NOT_AUTHORIZED,
            "lifetime": ERROR_LIFETIME,
            "epoch": EPOCH + 1,
            "nonce": REFUSED_NONCE,
            "internal_port": REFUSED_INTERNAL_PORT,
            "external_port": REFUSED_EXTERNAL_PORT,
        },
    )
    # The gateway grants this mapping, but its response arrives long after
    # the request; its epoch has advanced by the same amount.
    delayed = build_map_exchange(
        BASE_TIME + 0.004,
        {
            "lifetime": LIFETIME,
            "nonce": DELAYED_NONCE,
            "internal_port": DELAYED_INTERNAL_PORT,
            "external_port": DELAYED_EXTERNAL_PORT,
        },
        {
            "lifetime": LIFETIME,
            "epoch": EPOCH + 1 + int(LATE_RESPONSE_DELAY),
            "nonce": DELAYED_NONCE,
            "internal_port": DELAYED_INTERNAL_PORT,
            "external_port": DELAYED_EXTERNAL_PORT,
            "external_addr": EXTERNAL_MAPPED,
        },
        delay=LATE_RESPONSE_DELAY,
    )
    return success + failure + delayed


def main():
    packets = build_packets()
    wrpcap(str(Path(__file__).with_suffix("")), packets)


if __name__ == "__main__":
    main()
