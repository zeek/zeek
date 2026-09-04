#!/usr/bin/env python3
"""Generated with Claude Opus 4.8; adapted with Claude Opus 4.8 to use Scapy.

Generate a Kerberos-over-TCP pcap that stresses PKINIT pre-authentication state.

The AS-REQ carries PA_DATA_COUNT minimal PA-PK-AS-REQ (type 16) records. Each
record's padata-value is a short, degenerate blob that walks Zeek's PA-PK-AS-REQ
parser down to an empty certificate, which the x509 analyzer then rejects. So a
single small request exercises both the per-connection pa-data record cap
(KRB::max_pa_data_records) and a full file-analysis/x509 lifecycle per value.

Ethernet/IP/TCP framing and the pcap file are built with Scapy's high-level API.
The AS-REQ itself is encoded with Scapy's ASN.1 BER helpers rather than Scapy's
Kerberos PADATA layer: that layer models padata-value as an explicit
[2] { OCTET STRING }, whereas the parser under test needs the raw bytes to sit
directly inside the [2] tag so they line up with its field-by-field walk.
"""

import struct
from pathlib import Path

from scapy.all import IP, TCP, Ether, Raw, wrpcap
from scapy.asn1.asn1 import ASN1_INTEGER, ASN1_Codecs
from scapy.asn1.ber import BER_id_enc, BER_len_enc

CLIENT = "192.0.2.1"
SERVER = "192.0.2.2"
CLIENT_MAC = "02:00:00:00:00:01"
SERVER_MAC = "02:00:00:00:00:02"
CLIENT_PORT = 40000
SERVER_PORT = 88  # Kerberos
BASE_TIME = 1_700_000_000.0

# Number of PA-PK-AS-REQ records in the request. The btest redefines
# KRB::max_pa_data_records below this so the per-connection cap is exceeded.
PA_DATA_COUNT = 10
PKINIT_REQUEST_TYPE = 16  # PA-PK-AS-REQ


def ber_tag(tag, payload):
    """Wrap payload bytes in one BER tag-length-value field.

    Kerberos uses application ([APPLICATION 10]) and context ([1], [2], [3])
    tags that are not universal ASN.1 types, so the tag is supplied explicitly.
    The identifier and definite-length octets come from Scapy's BER encoders.
    """
    return BER_id_enc(tag) + BER_len_enc(len(payload)) + payload


def ber_integer(value):
    """Encode a universal ASN.1 INTEGER via Scapy's ASN.1 API."""
    return ASN1_INTEGER(value).enc(ASN1_Codecs.BER)


def padata_element():
    """Build one minimal PA-PK-AS-REQ pre-authentication value.

    The [2] padata-value holds 11 empty two-byte ASN.1 headers (22 bytes). Zeek
    reads them as the nested PA-PK-AS-REQ structure (OCTET STRING, SEQUENCEs,
    OID, version, digest algs, signed data, certificate), which bottoms out in a
    zero-length certificate that the x509 analyzer fails to parse.
    """
    structural_value = b"\x00\x00" * 11
    type_field = ber_tag(0xA1, ber_integer(PKINIT_REQUEST_TYPE))
    value_field = ber_tag(0xA2, structural_value)
    return ber_tag(0x30, type_field + value_field)


def krb_as_request():
    """Build one AS-REQ repeating the minimal PA-PK-AS-REQ value PA_DATA_COUNT times.

    The 4-byte big-endian length prefix is the Kerberos-over-TCP record mark.
    """
    padata = ber_tag(0xA3, ber_tag(0x30, padata_element() * PA_DATA_COUNT))
    version = ber_tag(0xA1, ber_integer(5))  # pvno
    message_type = ber_tag(0xA2, ber_integer(10))  # AS-REQ
    body = ber_tag(0xA4, ber_tag(0x30, b""))  # minimal (empty) KDC-REQ-BODY
    request = ber_tag(
        0x6A, ber_tag(0x30, version + message_type + padata + body)
    )  # [APPLICATION 10] SEQUENCE
    return struct.pack("!I", len(request)) + request


def pkt(is_orig, seq, ack, flags, payload=b""):
    """Build one TCP packet in the given direction."""
    if is_orig:
        src, dst, sport, dport = CLIENT, SERVER, CLIENT_PORT, SERVER_PORT
        eth_src, eth_dst = CLIENT_MAC, SERVER_MAC
    else:
        src, dst, sport, dport = SERVER, CLIENT, SERVER_PORT, CLIENT_PORT
        eth_src, eth_dst = SERVER_MAC, CLIENT_MAC
    p = (
        Ether(src=eth_src, dst=eth_dst)
        / IP(src=src, dst=dst)
        / TCP(sport=sport, dport=dport, seq=seq, ack=ack, flags=flags)
    )
    if payload:
        p = p / Raw(payload)
    return p


def build_packets():
    client_seq, server_seq = 1000, 5000
    packets = [
        pkt(True, client_seq, 0, "S"),
        pkt(False, server_seq, client_seq + 1, "SA"),
        pkt(True, client_seq + 1, server_seq + 1, "A"),
    ]
    client_seq += 1
    server_seq += 1

    request = krb_as_request()
    packets.append(pkt(True, client_seq, server_seq, "PA", request))
    client_seq += len(request)

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
