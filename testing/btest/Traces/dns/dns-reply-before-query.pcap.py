"""Generate a DNS trace where the reply is observed before the query."""

from pathlib import Path

from scapy.all import DNS, IP, rdpcap, wrpcap

source = Path(__file__).with_name("dns-shared-cname.pcap")
packets = rdpcap(str(source))

assert len(packets) == 2
assert packets[0][DNS].qr == 0
assert packets[1][DNS].qr == 1

request = packets[0][IP].copy()
response = packets[1][IP].copy()

response.time = 1763761597.0
request.time = 1763761597.005

wrpcap(str(Path(__file__).with_suffix("")), [response, request])
