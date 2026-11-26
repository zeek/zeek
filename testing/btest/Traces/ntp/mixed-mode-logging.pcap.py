"""Generate three UDP flows that switch NTP modes between messages.

Written with GPT-6 in OpenAI Codex using Scapy.
"""

from pathlib import Path

from scapy.all import IP, UDP, Ether, wrpcap
from scapy.layers.ntp import NTPControl, NTPHeader, NTPPrivate

BASE_TIME = 1_700_000_000.0


def main():
    client = NTPHeader(mode=3, stratum=0, id="0.0.0.0", orig=0, sent=3_908_988_800)
    reserved = client.copy()
    reserved.mode = 0
    # An implicit count adds a trailing byte in Scapy 2.6.1.
    control = NTPControl(version=4, op_code=1, sequence=1, count=0)
    private = NTPPrivate(version=3, implementation=3)

    flows = [
        (client, reserved),
        (control, client),
        (private, control),
    ]

    packets = [
        Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")
        / IP(src="192.0.2.1", dst="192.0.2.2")
        / UDP(sport=port, dport=123)
        / message
        for port, messages in enumerate(flows, start=40000)
        for message in messages
    ]
    for index, packet in enumerate(packets):
        packet.time = BASE_TIME + index * 0.001

    wrpcap(str(Path(__file__).with_suffix("")), packets)


if __name__ == "__main__":
    main()
