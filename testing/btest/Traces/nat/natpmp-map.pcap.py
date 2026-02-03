#!/usr/bin/env python3
"""Generates NAT-PMP (RFC 6886) TCP port mapping requests with a successful, a
failed, and a delayed response.

A client asks its gateway to map a fixed internal TCP port to a fixed external
port, and the gateway grants the mapping with the requested lifetime. The
client then asks for a second mapping, which the gateway refuses with a
non-zero result code and zeroed external port and lifetime. Finally, the
client asks for a third mapping, and the gateway only answers 45 seconds later,
which is past Zeek's default NAT-PMP request timeout.

Written with claude-opus-5-5 using Scapy.
"""

from pathlib import Path

from scapy.all import IP, UDP, ByteField, Ether, IntField, Packet, ShortField, wrpcap

CLIENT = "192.168.1.100"
GATEWAY = "192.168.1.1"
CLIENT_PORT = 54321
NATPMP_PORT = 5351
CLIENT_MAC = "02:00:00:00:00:01"
GATEWAY_MAC = "02:00:00:00:00:02"

INTERNAL_PORT = 8080
EXTERNAL_PORT = 18080
LIFETIME = 3600
EPOCH = 1234  # Gateway's seconds since start of epoch.

REFUSED_INTERNAL_PORT = 22
REFUSED_EXTERNAL_PORT = 2222

DELAYED_INTERNAL_PORT = 443
DELAYED_EXTERNAL_PORT = 8443
RESPONSE_DELAY = 0.001
LATE_RESPONSE_DELAY = 45.0  # Longer than NAT::request_timeout (30 secs).

OPCODE_MAP_TCP = 2
RESPONSE_BIT = 128
RESULT_SUCCESS = 0
RESULT_NOT_AUTHORIZED = 2  # Not Authorized/Refused

BASE_TIME = 1_700_000_000.0


class NATPMPMapRequest(Packet):
    name = "NAT-PMP Map Request"
    fields_desc = [
        ByteField("version", 0),
        ByteField("opcode", OPCODE_MAP_TCP),
        ShortField("reserved", 0),
        ShortField("internal_port", 0),
        ShortField("external_port", 0),
        IntField("lifetime", 0),
    ]


class NATPMPMapResponse(Packet):
    name = "NAT-PMP Map Response"
    fields_desc = [
        ByteField("version", 0),
        ByteField("opcode", RESPONSE_BIT + OPCODE_MAP_TCP),
        ShortField("result_code", RESULT_SUCCESS),
        IntField("epoch", 0),
        ShortField("internal_port", 0),
        ShortField("external_port", 0),
        IntField("lifetime", 0),
    ]


def build_map_exchange(start, request_fields, response_fields, delay=RESPONSE_DELAY):
    request = (
        Ether(src=CLIENT_MAC, dst=GATEWAY_MAC)
        / IP(src=CLIENT, dst=GATEWAY)
        / UDP(sport=CLIENT_PORT, dport=NATPMP_PORT)
        / NATPMPMapRequest(**request_fields)
    )
    response = (
        Ether(src=GATEWAY_MAC, dst=CLIENT_MAC)
        / IP(src=GATEWAY, dst=CLIENT)
        / UDP(sport=NATPMP_PORT, dport=CLIENT_PORT)
        / NATPMPMapResponse(**response_fields)
    )
    request.time = start
    response.time = start + delay
    return [request, response]


def build_packets():
    success = build_map_exchange(
        BASE_TIME,
        {
            "internal_port": INTERNAL_PORT,
            "external_port": EXTERNAL_PORT,
            "lifetime": LIFETIME,
        },
        {
            "epoch": EPOCH,
            "internal_port": INTERNAL_PORT,
            "external_port": EXTERNAL_PORT,
            "lifetime": LIFETIME,
        },
    )
    # On failure the gateway echoes the internal port, but the assigned
    # external port and lifetime are undefined; send them as zero.
    failure = build_map_exchange(
        BASE_TIME + 0.002,
        {
            "internal_port": REFUSED_INTERNAL_PORT,
            "external_port": REFUSED_EXTERNAL_PORT,
            "lifetime": LIFETIME,
        },
        {
            "result_code": RESULT_NOT_AUTHORIZED,
            "epoch": EPOCH + 1,
            "internal_port": REFUSED_INTERNAL_PORT,
            "external_port": 0,
            "lifetime": 0,
        },
    )
    # The gateway grants this mapping, but its response arrives long after
    # the request; its epoch has advanced by the same amount.
    delayed = build_map_exchange(
        BASE_TIME + 0.004,
        {
            "internal_port": DELAYED_INTERNAL_PORT,
            "external_port": DELAYED_EXTERNAL_PORT,
            "lifetime": LIFETIME,
        },
        {
            "epoch": EPOCH + 1 + int(LATE_RESPONSE_DELAY),
            "internal_port": DELAYED_INTERNAL_PORT,
            "external_port": DELAYED_EXTERNAL_PORT,
            "lifetime": LIFETIME,
        },
        delay=LATE_RESPONSE_DELAY,
    )
    return success + failure + delayed


def main():
    packets = build_packets()
    wrpcap(str(Path(__file__).with_suffix("")), packets)


if __name__ == "__main__":
    main()
