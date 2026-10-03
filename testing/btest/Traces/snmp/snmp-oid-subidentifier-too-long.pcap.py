#!/usr/bin/env python3
"""
Generate snmp-oid-subidentifier-too-long.pcap: an SNMPv1 get-request whose
single varbind carries an OID with an overlong subidentifier (ten 0x80
continuation bytes plus a terminator). Decoding that subidentifier shifts a
uint64 by 70 bits, which Zeek now rejects with the
asn_oid_subidentifier_too_long weird.

The SNMP message is built by hand because Scapy's SNMP layer cannot encode the
overlong subidentifier. MAC addresses and the timestamp are hardcoded so the
trace is reproducible.

Adapted with Claude Sonnet 5.5 (Anthropic) to be reproducible.
"""

from pathlib import Path

from scapy.all import IP, UDP, Ether, Raw, wrpcap

SRC_MAC = "02:00:00:00:00:02"
DST_MAC = "02:00:00:00:00:01"
BASE_TIME = 1_700_000_000.0


def tlv(tag, content):
    assert len(content) < 0x80, "short-form length only"
    return bytes([tag, len(content)]) + content


def main():
    # OID content: 0x2b (1.3) followed by one subidentifier made of ten 0x80
    # continuation bytes and a 0x00 terminator -> 11 bytes, shift count 70.
    oid_content = b"\x2b" + b"\x80" * 10 + b"\x00"
    oid = tlv(0x06, oid_content)
    null = b"\x05\x00"

    varbind = tlv(0x30, oid + null)
    varbind_list = tlv(0x30, varbind)

    pdu_body = (
        tlv(0x02, b"\x01")  # request-id
        + tlv(0x02, b"\x00")  # error-status
        + tlv(0x02, b"\x00")  # error-index
        + varbind_list
    )
    pdu = tlv(0xA0, pdu_body)  # get-request

    message = tlv(
        0x30,
        tlv(0x02, b"\x00")  # version (SNMPv1)
        + tlv(0x04, b"public")  # community
        + pdu,
    )

    pkt = (
        Ether(src=SRC_MAC, dst=DST_MAC)
        / IP(src="10.0.0.2", dst="10.0.0.1")
        / UDP(sport=40000, dport=161)
        / Raw(load=message)
    )

    pkt.time = BASE_TIME

    wrpcap(str(Path(__file__).with_suffix("")), [pkt])


if __name__ == "__main__":
    main()
