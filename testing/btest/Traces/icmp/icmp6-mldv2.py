#!/usr/bin/env python3
"""
Generate IPv6 Multicast Listener Discovery v2 (MLDv2) packets using Scapy.
Creates packets with multiple multicast address records and saves to a pcap file.
"""

import random

from scapy.all import (
    ICMPv6Unknown,
    IPv6,
    Raw,
    inet_pton,
    socket,
    struct,
    wrpcap,
)


def random_ipv6_multicast():
    """Generate a random IPv6 multicast address (ff00::/8)"""
    # Use ff02::/16 for link-local multicast
    return f"ff02::{random.randint(1, 0xFFFF):x}:{random.randint(0, 0xFFFF):x}"


def random_ipv6_link_local():
    """Generate a random IPv6 link-local address (fe80::/10)"""
    return f"fe80::{random.randint(1, 0xFFFF):x}:{random.randint(0, 0xFFFF):x}:{random.randint(0, 0xFFFF):x}"


def create_mldv2_report_packet(
    src_addr,
    multicast_records,
    override_source_counts=None,
    aux_data_blocks=None,
    override_aux_data_lens=None,
):
    """
    Create an MLDv2 Report packet with multiple multicast address records.

    Args:
        src_addr: Source IPv6 address
        multicast_records: List of tuples (record_type, multicast_address, source_addresses)
        override_source_counts: Optional list of integers to override the "Number of Sources" field
                                for each record (for testing malformed packets)
        aux_data_blocks: Optional list of bytes objects containing auxiliary data for each record
                         (Aux Data Len is in units of 32-bit words)
        override_aux_data_lens: Optional list of integers to override the "Aux Data Len" field
                                for each record (for testing malformed packets)
    """
    # Build the MLDv2 report manually
    # ICMPv6 Type 143 = MLDv2 Report

    # MLDv2 Multicast Address Record structure:
    # - Record Type (1 byte)
    # - Aux Data Len (1 byte) - in units of 32-bit words
    # - Number of Sources (2 bytes)
    # - Multicast Address (16 bytes)
    # - Source Addresses (16 bytes each)
    # - Auxiliary Data (variable length, padded to 32-bit boundary)

    records_data = b""
    for idx, (record_type, mcast_addr, source_addrs) in enumerate(multicast_records):
        # Record Type: 1=MODE_IS_INCLUDE, 2=MODE_IS_EXCLUDE, 3=CHANGE_TO_INCLUDE, 4=CHANGE_TO_EXCLUDE
        records_data += struct.pack("!B", record_type)

        # Aux Data Length (in 32-bit words)
        if override_aux_data_lens and idx < len(override_aux_data_lens):
            # Override aux data length for malformed packets
            aux_data_len_words = override_aux_data_lens[idx]
            records_data += struct.pack("!B", aux_data_len_words)
            aux_data = (
                aux_data_blocks[idx]
                if (aux_data_blocks and idx < len(aux_data_blocks))
                else b""
            )
        elif aux_data_blocks and idx < len(aux_data_blocks) and aux_data_blocks[idx]:
            aux_data = aux_data_blocks[idx]
            # Pad to 32-bit boundary if needed
            aux_data_len_words = (len(aux_data) + 3) // 4
            records_data += struct.pack("!B", aux_data_len_words)
        else:
            aux_data = b""
            records_data += struct.pack("!B", 0)

        # Number of Sources (can be overridden for malformed packets)
        if override_source_counts and idx < len(override_source_counts):
            num_sources = override_source_counts[idx]
        else:
            num_sources = len(source_addrs)
        records_data += struct.pack("!H", num_sources)

        # Multicast Address
        records_data += inet_pton(socket.AF_INET6, mcast_addr)

        # Source Addresses
        for src in source_addrs:
            records_data += inet_pton(socket.AF_INET6, src)

        # Auxiliary Data (if present)
        if aux_data:
            records_data += aux_data
            # Pad to 32-bit boundary
            padding_needed = (4 - (len(aux_data) % 4)) % 4
            if padding_needed:
                records_data += b"\x00" * padding_needed

    # MLDv2 Report header:
    # - Type (1 byte) = 143
    # - Code (1 byte) = 0
    # - Checksum (2 bytes) = calculated by Scapy
    # - Reserved (2 bytes)
    # - Number of Multicast Address Records (2 bytes)

    num_records = len(multicast_records)
    mldv2_data = struct.pack("!H", 0)  # Reserved
    mldv2_data += struct.pack("!H", num_records)  # Number of records
    mldv2_data += records_data

    # Create the packet
    pkt = (
        IPv6(src=src_addr, dst="ff02::16")
        / ICMPv6Unknown(type=143, code=0)
        / Raw(load=mldv2_data)
    )

    return pkt


def main():
    # Generate unique random link-local IPv6 source addresses for each packet
    src_addr1 = random_ipv6_link_local()
    src_addr2 = random_ipv6_link_local()
    src_addr3 = random_ipv6_link_local()
    src_addr4 = random_ipv6_link_local()
    src_addr5 = random_ipv6_link_local()

    print(f"Source Address 1: {src_addr1}")
    print(f"Source Address 2: {src_addr2}")
    print(f"Source Address 3: {src_addr3}")
    print(f"Source Address 4: {src_addr4}")
    print(f"Source Address 5: {src_addr5}")

    # Create multicast address records
    # Each record is (record_type, multicast_address, [source_addresses])
    multicast_records = [
        # MODE_IS_INCLUDE with 2 sources
        (1, random_ipv6_multicast(), [src_addr1, src_addr2]),
        # MODE_IS_EXCLUDE with 1 source
        (2, random_ipv6_multicast(), [src_addr1]),
        # CHANGE_TO_INCLUDE with 0 sources (leave group)
        (3, random_ipv6_multicast(), []),
        # CHANGE_TO_EXCLUDE with 1 source
        (4, random_ipv6_multicast(), [src_addr2]),
    ]

    print(
        f"\nCreating MLDv2 Report with {len(multicast_records)} multicast address records:"
    )
    for i, (rec_type, mcast_addr, sources) in enumerate(multicast_records, 1):
        record_types = {
            1: "MODE_IS_INCLUDE",
            2: "MODE_IS_EXCLUDE",
            3: "CHANGE_TO_INCLUDE",
            4: "CHANGE_TO_EXCLUDE",
        }
        print(
            f"  Record {i}: {record_types.get(rec_type, 'UNKNOWN')} - {mcast_addr} ({len(sources)} sources)"
        )

    # Create the packet (using unique source address)
    pkt1 = create_mldv2_report_packet(src_addr1, multicast_records)

    # Create a second packet with zero multicast address records
    print("\nCreating MLDv2 Report with 0 multicast address records:")
    print("  (Empty record list)")
    pkt2 = create_mldv2_report_packet(src_addr2, [])

    # Create a third packet with malformed record: claims 3 sources but only has 2
    malformed_record = [
        (1, random_ipv6_multicast(), [src_addr1, src_addr2])  # Actually 2 sources
    ]
    print("\nCreating MALFORMED MLDv2 Report with 1 multicast address record:")
    print(
        f"  Record 1: MODE_IS_INCLUDE - {malformed_record[0][1]} (claims 3 sources, actually has 2)"
    )
    pkt3 = create_mldv2_report_packet(
        src_addr3, malformed_record, override_source_counts=[3]
    )

    # Create a fourth packet with one source and auxiliary data
    aux_record = [
        (2, random_ipv6_multicast(), [src_addr1])  # MODE_IS_EXCLUDE with 1 source
    ]
    # Create 8 bytes of auxiliary data (will be 2 32-bit words)
    aux_data = b"\x01\x02\x03\x04\x05\x06\x07\x08"
    print("\nCreating MLDv2 Report with 1 multicast address record and auxiliary data:")
    print(
        f"  Record 1: MODE_IS_EXCLUDE - {aux_record[0][1]} (1 source, {len(aux_data)} bytes aux data)"
    )
    pkt4 = create_mldv2_report_packet(src_addr4, aux_record, aux_data_blocks=[aux_data])

    # Create a fifth packet with malformed aux data: claims aux data length > 0 but no actual data
    malformed_aux_record = [
        (1, random_ipv6_multicast(), [src_addr2])  # MODE_IS_INCLUDE with 1 source
    ]
    print("\nCreating MALFORMED MLDv2 Report with 1 multicast address record:")
    print(
        f"  Record 1: MODE_IS_INCLUDE - {malformed_aux_record[0][1]} (1 source, claims 2 words aux data, actually has 0)"
    )
    pkt5 = create_mldv2_report_packet(
        src_addr5, malformed_aux_record, override_aux_data_lens=[2]
    )

    # Save all packets to pcap file
    output_file = "icmp6-mldv2.pcap"
    wrpcap(output_file, [pkt1, pkt2, pkt3, pkt4, pkt5])

    print(f"\n✓ 5 packets written to {output_file}")
    print("\nTo view with tcpdump:")
    print(f"  tcpdump -r {output_file} -vvv")
    print("\nTo test with Zeek:")
    print(f"  zeek -r {output_file}")


if __name__ == "__main__":
    main()
