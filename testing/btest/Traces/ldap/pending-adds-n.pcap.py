#!/usr/bin/env python3

"""Generate an LDAP trace with many outstanding AddRequest message IDs.

The trace contains one TCP connection to port 389. The client sends many valid
LDAP AddRequest messages with unique message IDs and no AddResponse replies.
Zeek's LDAP script retains one pending MessageInfo record per message ID
until connection removal.

Adapted from pending-adds-n.pcap.py by Sonnet 4.6.
"""

from __future__ import annotations

import argparse

from scapy.all import IP, TCP, Ether, wrpcap


def ber_len(length: int) -> bytes:
    if length < 0x80:
        return bytes([length])
    encoded = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(encoded)]) + encoded


def tlv(tag: int, value: bytes) -> bytes:
    return bytes([tag]) + ber_len(len(value)) + value


def ber_int(value: int) -> bytes:
    encoded = value.to_bytes((value.bit_length() + 7) // 8 or 1, "big")
    if encoded[0] & 0x80:
        encoded = b"\x00" + encoded
    return tlv(0x02, encoded)


def ldap_add_request(message_id: int, entry_dn: str) -> bytes:
    """Build an LDAPMessage containing a minimal AddRequest.

    AddRequest ASN.1 [APPLICATION 8] SEQUENCE {
        entry       LDAPDN,
        attributes  AttributeList
    }

    One attribute (objectClass=top) is included to produce a valid message.
    """
    attr_type = tlv(0x04, b"objectClass")
    attr_val = tlv(0x04, b"top")
    attr_vals = tlv(0x31, attr_val)  # SET OF AttributeValue
    attribute = tlv(0x30, attr_type + attr_vals)
    attribute_list = tlv(0x30, attribute)

    request_body = tlv(0x04, entry_dn.encode("utf-8")) + attribute_list
    return tlv(0x30, ber_int(message_id) + tlv(0x68, request_body))


def build_packets(count: int, chunk_size: int, entry_dn: str):
    client = "10.0.0.1"
    server = "10.0.0.2"
    client_mac = "02:00:00:00:00:01"
    server_mac = "02:00:00:00:00:02"
    sport = 50000
    dport = 389
    client_seq = 1000
    server_seq = 9000

    packets = [
        Ether(src=client_mac, dst=server_mac)
        / IP(src=client, dst=server)
        / TCP(sport=sport, dport=dport, flags="S", seq=client_seq),
        Ether(src=server_mac, dst=client_mac)
        / IP(src=server, dst=client)
        / TCP(sport=dport, dport=sport, flags="SA", seq=server_seq, ack=client_seq + 1),
        Ether(src=client_mac, dst=server_mac)
        / IP(src=client, dst=server)
        / TCP(
            sport=sport, dport=dport, flags="A", seq=client_seq + 1, ack=server_seq + 1
        ),
    ]

    payload = b"".join(ldap_add_request(i, entry_dn) for i in range(1, count + 1))

    seq = client_seq + 1
    for offset in range(0, len(payload), chunk_size):
        chunk = payload[offset : offset + chunk_size]
        packets.append(
            Ether(src=client_mac, dst=server_mac)
            / IP(src=client, dst=server)
            / TCP(sport=sport, dport=dport, flags="PA", seq=seq, ack=server_seq + 1)
            / chunk
        )
        seq += len(chunk)

    return packets, len(payload)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-n",
        "--count",
        type=int,
        default=20000,
        help="number of LDAP AddRequest messages",
    )
    parser.add_argument(
        "-o", "--output", default="ldap-pending-adds.pcap", help="output pcap path"
    )
    parser.add_argument(
        "--chunk-size", type=int, default=1200, help="TCP payload bytes per packet"
    )
    parser.add_argument(
        "--entry-dn", default="cn=test,dc=example,dc=com", help="LDAP entry DN"
    )
    args = parser.parse_args()

    if args.count < 1:
        raise SystemExit("--count must be positive")

    packets, payload_len = build_packets(args.count, args.chunk_size, args.entry_dn)
    wrpcap(args.output, packets)
    print(
        f"wrote {args.output}: requests={args.count} ldap_payload_bytes={payload_len} packets={len(packets)}"
    )


if __name__ == "__main__":
    main()
