#!/usr/bin/env python3
"""Build a pcap with a DTLS handshake (ClientHello + ServerHello). Sequence numbers
jump.

The ClientHello is split across three DTLS handshake fragments (each in its
own UDP datagram / DTLS record). The ServerHello is sent as a single record.

The DTLS records are built by hand because Scapy has no DTLS record layer. The
hello randoms, MAC addresses and timestamps are hardcoded, so running the script
reproduces the committed trace.

Adapted with Claude Sonnet 5.5 (Anthropic) to be reproducible.
"""

from pathlib import Path

from scapy.all import IP, UDP, Ether, wrpcap

CLIENT_MAC = "02:00:00:00:00:01"
SERVER_MAC = "02:00:00:00:00:02"
CLIENT_IP = "10.0.0.1"
SERVER_IP = "10.0.0.2"
CLIENT_PORT = 50000
SERVER_PORT = 4433

DTLS_1_2 = 0xFEFD

BASE_TIME = 1_700_000_000.0

# Hardcoded hello randoms (taken from the committed trace).
CLIENT_RANDOM = bytes.fromhex(
    "f2d120880f75811062381f06abf371f75899aea4af864c63830b9b3ac7a09a71"
)
SERVER_RANDOM = bytes.fromhex(
    "f35685288b91050cf331886c7c6f5a69e7c059b71e7e1b621cdc4c0e80cd1b10"
)


def build_extensions(exts):
    """exts: list of (ext_type, ext_data_bytes). Returns extensions block
    including its 2-byte total length prefix."""
    body = b"".join(
        t.to_bytes(2, "big") + len(d).to_bytes(2, "big") + d for t, d in exts
    )
    return len(body).to_bytes(2, "big") + body


def build_client_hello_body(cookie=b""):
    """Build a DTLS 1.2 ClientHello body (without the handshake header).

    DTLS ClientHello layout:
      ProtocolVersion (2)
      Random (32)
      SessionID (1-byte length + data)
      Cookie (1-byte length + data)         <-- DTLS-specific
      CipherSuites (2-byte length + data)
      CompressionMethods (1-byte length + data)
      Extensions (2-byte length + data)
    """
    version = DTLS_1_2.to_bytes(2, "big")
    random = CLIENT_RANDOM
    session_id = b"\x00"  # zero-length
    cookie_field = bytes([len(cookie)]) + cookie

    ciphers = [0x1301, 0x1302, 0x1303, 0xC02B, 0xC02F]
    cipher_bytes = b"".join(c.to_bytes(2, "big") for c in ciphers)
    cipher_field = len(cipher_bytes).to_bytes(2, "big") + cipher_bytes

    compression_field = b"\x01\x00"  # length 1, method 0 (null)

    # Extensions: supported_versions, supported_groups, signature_algorithms
    sv_data = bytes([4]) + (0xFEFC).to_bytes(2, "big") + DTLS_1_2.to_bytes(2, "big")
    groups = [0x001D, 0x0017]  # x25519, secp256r1
    sg_inner = b"".join(g.to_bytes(2, "big") for g in groups)
    sg_data = len(sg_inner).to_bytes(2, "big") + sg_inner
    sigs = [0x0804, 0x0403]  # rsa_pss_rsae_sha256, ecdsa_secp256r1_sha256
    sa_inner = b"".join(s.to_bytes(2, "big") for s in sigs)
    sa_data = len(sa_inner).to_bytes(2, "big") + sa_inner

    extensions = build_extensions(
        [
            (43, sv_data),  # supported_versions
            (10, sg_data),  # supported_groups
            (13, sa_data),  # signature_algorithms
        ]
    )

    return (
        version
        + random
        + session_id
        + cookie_field
        + cipher_field
        + compression_field
        + extensions
    )


def build_server_hello_body():
    """Build a DTLS 1.2 ServerHello body (no cookie field — that's CH-only)."""
    version = DTLS_1_2.to_bytes(2, "big")
    random = SERVER_RANDOM
    session_id = b"\x00"
    cipher = (0x1301).to_bytes(2, "big")
    compression = b"\x00"

    sv_data = (0xFEFC).to_bytes(2, "big")
    extensions = build_extensions([(43, sv_data)])  # supported_versions

    return version + random + session_id + cipher + compression + extensions


def build_dtls_record(
    content_type,
    version,
    epoch,
    seq,
    payload,
    *,
    msg_type=None,
    msg_seq=None,
    frag_offset=None,
    frag_len=None,
    total_len=None,
):
    """Build a DTLS record. For handshake records, prepend the 12-byte
    DTLS handshake header (msg_type, length, msg_seq, frag_offset, frag_len)."""
    if content_type == 22:  # handshake
        hs_header = (
            bytes([msg_type])
            + total_len.to_bytes(3, "big")
            + msg_seq.to_bytes(2, "big")
            + frag_offset.to_bytes(3, "big")
            + frag_len.to_bytes(3, "big")
        )
        body = hs_header + payload
    else:
        body = payload

    return (
        bytes([content_type])
        + version.to_bytes(2, "big")
        + epoch.to_bytes(2, "big")
        + seq.to_bytes(6, "big")
        + len(body).to_bytes(2, "big")
        + body
    )


def main():
    ch_body = build_client_hello_body()
    sh_body = build_server_hello_body()

    total_ch = len(ch_body)
    f1 = total_ch // 3
    f2 = total_ch // 3
    fragments = [
        (0, ch_body[:f1]),
        (f1, ch_body[f1 : f1 + f2]),
        (f1 + f2, ch_body[f1 + f2 :]),
    ]

    pkts = []

    for i, (off, frag) in enumerate(fragments):
        record = build_dtls_record(
            content_type=22,
            version=DTLS_1_2,
            epoch=0,
            seq=i * 128,
            payload=frag,
            msg_type=1,  # client_hello
            msg_seq=0,
            frag_offset=off,
            frag_len=len(frag),
            total_len=total_ch,
        )
        pkts.append(
            Ether(src=CLIENT_MAC, dst=SERVER_MAC)
            / IP(src=CLIENT_IP, dst=SERVER_IP)
            / UDP(sport=CLIENT_PORT, dport=SERVER_PORT)
            / record
        )

    sh_record = build_dtls_record(
        content_type=22,
        version=DTLS_1_2,
        epoch=0,
        seq=0,
        payload=sh_body,
        msg_type=2,  # server_hello
        msg_seq=0,
        frag_offset=0,
        frag_len=len(sh_body),
        total_len=len(sh_body),
    )
    pkts.append(
        Ether(src=SERVER_MAC, dst=CLIENT_MAC)
        / IP(src=SERVER_IP, dst=CLIENT_IP)
        / UDP(sport=SERVER_PORT, dport=CLIENT_PORT)
        / sh_record
    )

    for index, p in enumerate(pkts):
        p.time = BASE_TIME + index * 0.001

    wrpcap(str(Path(__file__).with_suffix("")), pkts)


if __name__ == "__main__":
    main()
