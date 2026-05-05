#!/usr/bin/env python3
"""
Generate an IPv6 Multicast Listener Discovery (MLD) Query packet using scapy.
MLD uses ICMPv6 type 130 for Multicast Listener Query.
Writes the packet to icmp6-mld-query.pcap for testing purposes.
"""

import random

from scapy.all import (
    ICMPv6MLQuery,
    IPv6,
    IPv6ExtHdrHopByHop,
    RouterAlert,
    wrpcap,
)


def generate_random_ipv6():
    """Generate a random IPv6 address."""
    return f"2001:db8::{random.randint(0, 0xFFFF):x}:{random.randint(0, 0xFFFF):x}"


def create_mld_packet():
    """
    Create an MLDv1 Query packet and write it to a pcap file.
    """
    # Generate random addresses
    src_addr = generate_random_ipv6()
    multicast_group = "ff02::1"  # All-nodes multicast address

    print("=" * 60)
    print("Generating MLDv1 Query Packet")
    print("=" * 60)
    print(f"Source Address: {src_addr}")
    print(f"Destination: {multicast_group}")
    print()

    # MLDv1 Query packet
    print("Creating MLDv1 Query packet...")
    ipv6 = IPv6(
        src=src_addr,
        dst=multicast_group,
        hlim=1,  # Hop limit must be 1 for MLD
    )

    # Create Hop-by-Hop options with Router Alert (RFC 2711)
    hopbyhop = IPv6ExtHdrHopByHop(
        options=[RouterAlert(value=0)]  # 0 = MLD
    )

    # Create ICMPv6 MLDv1 Query
    mld_query = ICMPv6MLQuery(
        mrd=10000,  # Maximum Response Delay (10 seconds)
        mladdr="::",  # General query (all multicast addresses)
    )

    packet = ipv6 / hopbyhop / mld_query

    print("MLDv1 packet created")
    packet.show()
    print()

    # Write packet to pcap file
    output_file = "icmp6-mld-query.pcap"
    wrpcap(output_file, packet)

    print("=" * 60)
    print(f"Successfully wrote packet to {output_file}")
    print("=" * 60)


if __name__ == "__main__":
    create_mld_packet()
