"""Two raw Ethernet frames with distinct source MACs.

The first frame triggers a parse error in the test analyzer. The second must
see its own $packet, not the failed frame's. Verifies that the cached packet
header is not stale after an %error event.

Written with Claude Opus 4.6 using Scapy.
"""

from pathlib import Path

from scapy.layers.l2 import Ether
from scapy.packet import Raw
from scapy.utils import wrpcap

BASE_TIME = 1_700_000_000.0

packets = [
    Ether(src="00:00:00:00:00:01", type=0x6666) / Raw(b"\xff".ljust(45, b"\x00")),
    Ether(src="00:00:00:00:00:02", type=0x6666) / Raw(b"\x01".ljust(45, b"\x00")),
]

for index, p in enumerate(packets):
    p.time = BASE_TIME + index * 0.001

wrpcap(str(Path(__file__).with_suffix("")), packets)
