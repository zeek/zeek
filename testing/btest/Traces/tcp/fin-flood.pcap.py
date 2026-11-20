#!/usr/bin/env python3
"""TCP FIN flood with alternating sequence numbers grows connection history.

After a normal three-way handshake the originator sends a flood of FIN/ACK
segments whose sequence number alternates between ISN+1 and ISN+2. Zeek only
records another 'F' in the connection history when a FIN's rel_seq+len differs
from the previous one (hist_last_FIN, see TCPSessionAdapter.cc), so alternating
the sequence number appends an 'F' for every single FIN. Without a bound this
grows the history string without limit; it is now capped by
max_connection_history_size, at which point a max_connection_history_size_reached
weird fires. A test can redef that option to a low value to observe the cap
against this trace.

The connection is deliberately never closed cleanly -- the FIN flood is the
behavior under test.

Original hand-rolled struct/pcap reproducer rewritten with Claude Opus 4.8
to use Scapy's high-level API.
"""

from pathlib import Path

from scapy.all import IP, TCP, Ether, wrpcap

CLIENT = "192.0.2.1"
SERVER = "192.0.2.2"
CLIENT_PORT = 40000
SERVER_PORT = 80
ISN_CLIENT = 1000
ISN_SERVER = 5000
BASE_TIME = 1_700_000_000.0

# Number of FIN/ACK segments in the flood. Each one appends an 'F'; a test can
# redef max_connection_history_size below this to observe the cap and weird.
FIN_COUNT = 100


def pkt(is_orig, seq, ack, flags):
    if is_orig:
        src, dst, sport, dport = CLIENT, SERVER, CLIENT_PORT, SERVER_PORT
        eth_src, eth_dst = "02:00:00:00:00:01", "02:00:00:00:00:02"
    else:
        src, dst, sport, dport = SERVER, CLIENT, SERVER_PORT, CLIENT_PORT
        eth_src, eth_dst = "02:00:00:00:00:02", "02:00:00:00:00:01"
    return (
        Ether(src=eth_src, dst=eth_dst)
        / IP(src=src, dst=dst)
        / TCP(sport=sport, dport=dport, seq=seq, ack=ack, flags=flags)
    )


def build_packets():
    packets = [
        pkt(True, ISN_CLIENT, 0, "S"),
        pkt(False, ISN_SERVER, ISN_CLIENT + 1, "SA"),
        pkt(True, ISN_CLIENT + 1, ISN_SERVER + 1, "A"),
    ]

    # FIN flood: alternate the sequence number between ISN+1 and ISN+2 so every
    # FIN's rel_seq+len differs from the previous one and gets its own 'F'.
    for i in range(FIN_COUNT):
        seq = ISN_CLIENT + 1 + (i & 1)
        packets.append(pkt(True, seq, ISN_SERVER + 1, "FA"))

    return packets


def main():
    packets = build_packets()

    # Assign reproducible, monotonically increasing timestamps.
    for index, p in enumerate(packets):
        p.time = BASE_TIME + index * 0.001

    wrpcap(str(Path(__file__).with_suffix("")), packets)


if __name__ == "__main__":
    main()
