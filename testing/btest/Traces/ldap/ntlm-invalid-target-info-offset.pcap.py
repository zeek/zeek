#!/usr/bin/env python3
"""Generate ntlm-invalid-target-info-offset.pcap: an LDAP/NTLM capture where
the NTLM_Challenge target_info_fields.offset is set to an invalid value
(less than the absolute offset of the payload), triggering an analyzer
violation for "invalid NTLM target info offset".
"""

from __future__ import annotations

import argparse
import struct
from pathlib import Path

from scapy.all import IP, TCP, Ether, Raw, wrpcap

CLIENT = "192.0.2.1"
SERVER = "192.0.2.2"
SPORT = 40000
DPORT = 389

NEGOTIATE_UNICODE = 0x00000001
NEGOTIATE_TARGET_INFO = 0x00800000
REQUEST_TARGET = 0x00000004
BASE_TIME = 1_700_000_000.0


def ber_length(size: int) -> bytes:
    if size < 0x80:
        return bytes([size])
    encoded = size.to_bytes((size.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(encoded)]) + encoded


def ber_tlv(tag: int, value: bytes) -> bytes:
    return bytes([tag]) + ber_length(len(value)) + value


def ntlm_challenge() -> bytes:
    """Build a challenge with an invalid target_info offset (set to 0)."""
    flags = NEGOTIATE_UNICODE | NEGOTIATE_TARGET_INFO

    # NTLM_Challenge fixed fields before payload:
    #   target_name_fields (8 bytes): length(2) + max_length(2) + offset(4)
    #   flags (4 bytes)
    #   challenge (8 bytes)
    #   reserved (8 bytes)
    #   target_info_fields (8 bytes): length(2) + max_length(2) + offset(4)
    # Total = 36 bytes of record fields
    # With the 12-byte SSP header (signature + msg_type), the absolute offset
    # of payload is 48.

    target_name_length = 0
    target_name_offset = 48  # valid, points to start of payload

    # Set target_info offset to 0 -- well below the absolute_offset of 48,
    # which will trigger the "invalid NTLM target info offset" violation.
    target_info_length = 4
    target_info_offset = 0  # INVALID

    payload = b"\x00" * 16  # some dummy payload bytes

    token = bytearray(b"NTLMSSP\x00")  # signature (8)
    token += struct.pack("<I", 2)  # msg_type = Challenge (4)
    # target_name_fields
    token += struct.pack(
        "<HHI", target_name_length, target_name_length, target_name_offset
    )
    # flags
    token += struct.pack("<I", flags)
    # challenge
    token += struct.pack("<Q", 0x0102030405060708)
    # reserved
    token += bytes(8)
    # target_info_fields
    token += struct.pack(
        "<HHI", target_info_length, target_info_length, target_info_offset
    )
    # payload
    token += payload

    return bytes(token)


def ldap_bind_response() -> bytes:
    """Build an LDAP BindResponse carrying the NTLM challenge token."""
    # Wrap in GSS-API/SPNEGO-like structure that Zeek's LDAP analyzer forwards
    # to the NTLM analyzer. Use a simple saslCredentials wrapper.
    challenge = ntlm_challenge()
    # BindResponse: resultCode=saslBindInProgress(14), matchedDN="", diagnosticMessage=""
    result_code = ber_tlv(0x0A, b"\x0e")
    matched_dn = ber_tlv(0x04, b"")
    diag_msg = ber_tlv(0x04, b"")
    # serverSaslCreds [7] OCTET STRING OPTIONAL
    sasl_creds = bytes([0x87]) + ber_length(len(challenge)) + challenge
    bind_response = result_code + matched_dn + diag_msg + sasl_creds
    # BindResponse is APPLICATION 1 (0x61)
    protocol_op = ber_tlv(0x61, bind_response)
    return ber_tlv(0x30, ber_tlv(0x02, b"\x01") + protocol_op)


def ldap_bind_request() -> bytes:
    """Build a simple LDAP BindRequest with SASL/NTLM negotiate."""
    # Build a minimal NTLM Negotiate message
    negotiate = bytearray(b"NTLMSSP\x00")
    negotiate += struct.pack("<I", 1)  # msg_type = Negotiate
    negotiate += struct.pack("<I", NEGOTIATE_UNICODE | NEGOTIATE_TARGET_INFO)
    negotiate += struct.pack("<HHI", 0, 0, 32)  # domain fields
    negotiate += struct.pack("<HHI", 0, 0, 32)  # workstation fields

    credentials = ber_tlv(0x04, bytes(negotiate))
    sasl = ber_tlv(0x04, b"NTLM") + credentials
    bind = ber_tlv(0x02, b"\x03") + ber_tlv(0x04, b"") + ber_tlv(0xA3, sasl)
    protocol_op = ber_tlv(0x60, bind)
    return ber_tlv(0x30, ber_tlv(0x02, b"\x01") + protocol_op)


def build_packets():
    """Build TCP handshake, LDAP bind request, and response with bad NTLM challenge."""
    pkts = []
    seq_c = 1000
    seq_s = 2000

    def client_pkt(flags, payload=b""):
        nonlocal seq_c, seq_s
        p = (
            Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")
            / IP(src=CLIENT, dst=SERVER)
            / TCP(
                sport=SPORT,
                dport=DPORT,
                flags=flags,
                seq=seq_c,
                ack=seq_s if "A" in flags else 0,
            )
        )
        if payload:
            p = p / Raw(payload)
        seq_c += len(payload) + (1 if "S" in flags or "F" in flags else 0)
        p.time = BASE_TIME + len(pkts)
        pkts.append(p)

    def server_pkt(flags, payload=b""):
        nonlocal seq_c, seq_s
        p = (
            Ether(src="02:00:00:00:00:02", dst="02:00:00:00:00:01")
            / IP(src=SERVER, dst=CLIENT)
            / TCP(
                sport=DPORT,
                dport=SPORT,
                flags=flags,
                seq=seq_s,
                ack=seq_c if "A" in flags else 0,
            )
        )
        if payload:
            p = p / Raw(payload)
        seq_s += len(payload) + (1 if "S" in flags or "F" in flags else 0)
        p.time = BASE_TIME + len(pkts)
        pkts.append(p)

    # TCP handshake
    client_pkt("S")
    server_pkt("SA")
    client_pkt("A")

    # Client sends LDAP BindRequest with NTLM Negotiate
    request = ldap_bind_request()
    client_pkt("PA", request)

    # Server sends LDAP BindResponse with invalid NTLM Challenge
    response = ldap_bind_response()
    server_pkt("PA", response)

    # Teardown
    client_pkt("FA")
    server_pkt("FA")
    client_pkt("A")

    return pkts


def main() -> None:
    default_output = Path(__file__).with_suffix("")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        default=default_output,
        help="output pcap path (default: %(default)s)",
    )
    args = parser.parse_args()

    pkts = build_packets()
    wrpcap(str(args.output), pkts)
    print(f"Wrote {len(pkts)} packets to {args.output}")


if __name__ == "__main__":
    main()
