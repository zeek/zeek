#!/usr/bin/env python3
"""HTTP transfer of a PE binary whose COFF NumberOfSections is oversized.

Exercises PE::max_number_of_sections (pe-file-headers.pac): the &enforce on
File_Header.NumberOfSections fires while parsing that 16-bit field, which lives
at offset 70 of the image -- well before any section bodies -- so the PE only
needs a DOS header, PE signature, and COFF File_Header with NumberOfSections set
past the limit (default 96). No section table is required to trip the check.

Generated with OpenAI Codex, adapted with Claude Opus 4.8 to use Scapy.
"""

import struct
from pathlib import Path

from scapy.all import IP, TCP, Ether, Raw, wrpcap

CLIENT = "192.0.2.1"
SERVER = "192.0.2.2"
CLIENT_PORT = 40000
SERVER_PORT = 80  # HTTP
BASE_TIME = 1_700_000_000.0

# NumberOfSections to advertise; well past the default cap of 96.
NUMBER_OF_SECTIONS = 0xFFFF


def build_pe(nsections):
    # Scapy has no PE layer, so hand-build the minimal image the check needs.
    # DOS header: "MZ", padding out to offset 60 where the 4-byte e_lfanew
    # (AddressOfNewExeHeader) points the PE header at offset 64.
    dos = b"MZ" + b"\x00" * 58 + struct.pack("<I", 64)
    # PE signature "PE\0\0" followed by the 20-byte COFF File_Header:
    #   Machine, NumberOfSections, TimeDateStamp, PointerToSymbolTable,
    #   NumberOfSymbols, SizeOfOptionalHeader, Characteristics.
    file_header = struct.pack(
        "<HHIIIHH",
        0x014C,  # Machine = IMAGE_FILE_MACHINE_I386
        nsections,  # NumberOfSections (the field under test)
        0,  # TimeDateStamp
        0,  # PointerToSymbolTable
        0,  # NumberOfSymbols
        0x00E0,  # SizeOfOptionalHeader
        0x0102,  # Characteristics
    )
    return dos + b"PE\x00\x00" + file_header


def pkt(is_orig, seq, ack, flags, payload=b""):
    if is_orig:
        src, dst, sport, dport = CLIENT, SERVER, CLIENT_PORT, SERVER_PORT
        eth_src, eth_dst = "02:00:00:00:00:01", "02:00:00:00:00:02"
    else:
        src, dst, sport, dport = SERVER, CLIENT, SERVER_PORT, CLIENT_PORT
        eth_src, eth_dst = "02:00:00:00:00:02", "02:00:00:00:00:01"
    p = (
        Ether(src=eth_src, dst=eth_dst)
        / IP(src=src, dst=dst)
        / TCP(sport=sport, dport=dport, seq=seq, ack=ack, flags=flags)
    )
    if payload:
        p = p / Raw(payload)
    return p


def build_packets():
    pe = build_pe(NUMBER_OF_SECTIONS)
    request = b"GET /excessive.exe HTTP/1.1\r\nHost: x\r\n\r\n"
    response = (
        b"HTTP/1.1 200 OK\r\n"
        b"Content-Type: application/x-dosexec\r\n"
        b"Content-Length: " + str(len(pe)).encode() + b"\r\n\r\n" + pe
    )

    client_seq, server_seq = 1000, 2000
    packets = [
        pkt(True, client_seq, 0, "S"),
        pkt(False, server_seq, client_seq + 1, "SA"),
        pkt(True, client_seq + 1, server_seq + 1, "A"),
    ]
    client_seq += 1
    server_seq += 1

    packets.append(pkt(True, client_seq, server_seq, "PA", request))
    client_seq += len(request)
    packets.append(pkt(False, server_seq, client_seq, "PA", response))
    server_seq += len(response)

    # Client ACKs the response first (clears the unacknowledged server data),
    # then a clean client-initiated FIN/ACK teardown (a FIN consumes one seq).
    packets.append(pkt(True, client_seq, server_seq, "A"))
    packets.append(pkt(True, client_seq, server_seq, "FA"))
    client_seq += 1
    packets.append(pkt(False, server_seq, client_seq, "FA"))
    server_seq += 1
    packets.append(pkt(True, client_seq, server_seq, "A"))
    return packets


def main():
    packets = build_packets()

    # Assign reproducible, monotonically increasing timestamps.
    for index, p in enumerate(packets):
        p.time = BASE_TIME + index * 0.001

    wrpcap(str(Path(__file__).with_suffix("")), packets)


if __name__ == "__main__":
    main()
