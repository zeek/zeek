#!/usr/bin/env python3
"""Generates PCP (RFC 6887) TCP PEER requests with a successful, a failed, and
a delayed response.

A client with outbound TCP connections to remote peers asks its gateway to
manage the mappings for those connections. The gateway grants the first
request with the requested lifetime and reports the external address and port
it assigned. The client then sends a second PEER request, which the gateway
refuses with a non-zero result code. Finally, the client sends a third PEER
request, and the gateway only answers 45 seconds later, which is past Zeek's
default NAT request timeout.

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

# Remote peers of the client's outbound connections.
REMOTE_PEER = "198.51.100.10"
REFUSED_REMOTE_PEER = "198.51.100.20"
DELAYED_REMOTE_PEER = "198.51.100.30"

# PCP carries IPv4 addresses as IPv4-mapped IPv6 addresses (RFC 6887, 5).
CLIENT_MAPPED = "::ffff:" + CLIENT
EXTERNAL_MAPPED = "::ffff:" + EXTERNAL
ANY_IPV4_MAPPED = "::ffff:0.0.0.0"  # No external address preference.
REMOTE_PEER_MAPPED = "::ffff:" + REMOTE_PEER
REFUSED_REMOTE_PEER_MAPPED = "::ffff:" + REFUSED_REMOTE_PEER
DELAYED_REMOTE_PEER_MAPPED = "::ffff:" + DELAYED_REMOTE_PEER

INTERNAL_PORT = 50000
EXTERNAL_PORT = 60000
REMOTE_PEER_PORT = 443
LIFETIME = 3600
EPOCH = 1234  # Gateway's seconds since start of epoch.

REFUSED_INTERNAL_PORT = 50001
REFUSED_EXTERNAL_PORT = 60001
REFUSED_REMOTE_PEER_PORT = 22
ERROR_LIFETIME = 1800  # Long lifetime error (RFC 6887, 7.4).

DELAYED_INTERNAL_PORT = 50002
DELAYED_EXTERNAL_PORT = 60002
DELAYED_REMOTE_PEER_PORT = 8443
RESPONSE_DELAY = 0.001
LATE_RESPONSE_DELAY = 45.0  # Longer than NAT::request_timeout (30 secs).

# Fixed nonces keep the output reproducible; each mapping uses its own.
SUCCESS_NONCE = bytes.fromhex("0102030405060708090a0b0c")
REFUSED_NONCE = bytes.fromhex("1112131415161718191a1b1c")
DELAYED_NONCE = bytes.fromhex("2122232425262728292a2b2c")

PCP_VERSION = 2
OPCODE_PEER = 2
PROTO_TCP = 6
RESULT_SUCCESS = 0
RESULT_NOT_AUTHORIZED = 2

BASE_TIME = 1_700_000_000.0


def peer_fields():
    """PEER opcode-specific fields (RFC 6887, 12.1), shared by requests and
    responses. The first part is identical to the MAP opcode fields."""
    return [
        StrFixedLenField("nonce", b"\x00" * 12, 12),
        ByteField("protocol", PROTO_TCP),
        X3BytesField("reserved_peer", 0),
        ShortField("internal_port", 0),
        ShortField("external_port", 0),
        IP6Field("external_addr", ANY_IPV4_MAPPED),
        ShortField("remote_peer_port", 0),
        ShortField("reserved_remote", 0),
        IP6Field("remote_peer_addr", ANY_IPV4_MAPPED),
    ]


class PCPPeerRequest(Packet):
    name = "PCP Peer Request"
    fields_desc = [
        ByteField("version", PCP_VERSION),
        BitField("response", 0, 1),
        BitField("opcode", OPCODE_PEER, 7),
        ShortField("reserved", 0),
        IntField("lifetime", 0),
        IP6Field("client_addr", CLIENT_MAPPED),
        *peer_fields(),
    ]


class PCPPeerResponse(Packet):
    name = "PCP Peer Response"
    fields_desc = [
        ByteField("version", PCP_VERSION),
        BitField("response", 1, 1),
        BitField("opcode", OPCODE_PEER, 7),
        ByteField("reserved", 0),
        ByteField("result_code", RESULT_SUCCESS),
        IntField("lifetime", 0),
        IntField("epoch", 0),
        StrFixedLenField("reserved_resp", b"\x00" * 12, 12),
        *peer_fields(),
    ]


def build_peer_exchange(start, request_fields, response_fields, delay=RESPONSE_DELAY):
    request = (
        Ether(src=CLIENT_MAC, dst=GATEWAY_MAC)
        / IP(src=CLIENT, dst=GATEWAY)
        / UDP(sport=CLIENT_PORT, dport=PCP_PORT)
        / PCPPeerRequest(**request_fields)
    )
    response = (
        Ether(src=GATEWAY_MAC, dst=CLIENT_MAC)
        / IP(src=GATEWAY, dst=CLIENT)
        / UDP(sport=PCP_PORT, dport=CLIENT_PORT)
        / PCPPeerResponse(**response_fields)
    )
    request.time = start
    response.time = start + delay
    return [request, response]


def build_packets():
    # The gateway copies the remote peer fields from the request into the
    # response (RFC 6887, 12.3).
    success = build_peer_exchange(
        BASE_TIME,
        {
            "lifetime": LIFETIME,
            "nonce": SUCCESS_NONCE,
            "internal_port": INTERNAL_PORT,
            "external_port": EXTERNAL_PORT,
            "remote_peer_port": REMOTE_PEER_PORT,
            "remote_peer_addr": REMOTE_PEER_MAPPED,
        },
        {
            "lifetime": LIFETIME,
            "epoch": EPOCH,
            "nonce": SUCCESS_NONCE,
            "internal_port": INTERNAL_PORT,
            "external_port": EXTERNAL_PORT,
            "external_addr": EXTERNAL_MAPPED,
            "remote_peer_port": REMOTE_PEER_PORT,
            "remote_peer_addr": REMOTE_PEER_MAPPED,
        },
    )
    # On failure the gateway copies the PEER fields from the request
    # (RFC 6887, 7.2), and the lifetime says how long the error is valid.
    failure = build_peer_exchange(
        BASE_TIME + 0.002,
        {
            "lifetime": LIFETIME,
            "nonce": REFUSED_NONCE,
            "internal_port": REFUSED_INTERNAL_PORT,
            "external_port": REFUSED_EXTERNAL_PORT,
            "remote_peer_port": REFUSED_REMOTE_PEER_PORT,
            "remote_peer_addr": REFUSED_REMOTE_PEER_MAPPED,
        },
        {
            "result_code": RESULT_NOT_AUTHORIZED,
            "lifetime": ERROR_LIFETIME,
            "epoch": EPOCH + 1,
            "nonce": REFUSED_NONCE,
            "internal_port": REFUSED_INTERNAL_PORT,
            "external_port": REFUSED_EXTERNAL_PORT,
            "remote_peer_port": REFUSED_REMOTE_PEER_PORT,
            "remote_peer_addr": REFUSED_REMOTE_PEER_MAPPED,
        },
    )
    # The gateway grants this mapping, but its response arrives long after
    # the request; its epoch has advanced by the same amount.
    delayed = build_peer_exchange(
        BASE_TIME + 0.004,
        {
            "lifetime": LIFETIME,
            "nonce": DELAYED_NONCE,
            "internal_port": DELAYED_INTERNAL_PORT,
            "external_port": DELAYED_EXTERNAL_PORT,
            "remote_peer_port": DELAYED_REMOTE_PEER_PORT,
            "remote_peer_addr": DELAYED_REMOTE_PEER_MAPPED,
        },
        {
            "lifetime": LIFETIME,
            "epoch": EPOCH + 1 + int(LATE_RESPONSE_DELAY),
            "nonce": DELAYED_NONCE,
            "internal_port": DELAYED_INTERNAL_PORT,
            "external_port": DELAYED_EXTERNAL_PORT,
            "external_addr": EXTERNAL_MAPPED,
            "remote_peer_port": DELAYED_REMOTE_PEER_PORT,
            "remote_peer_addr": DELAYED_REMOTE_PEER_MAPPED,
        },
        delay=LATE_RESPONSE_DELAY,
    )
    return success + failure + delayed


def main():
    packets = build_packets()
    wrpcap(str(Path(__file__).with_suffix("")), packets)


if __name__ == "__main__":
    main()
