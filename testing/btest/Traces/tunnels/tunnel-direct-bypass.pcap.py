#!/usr/bin/env python3

from scapy.all import GRE, IP, TCP, Ether, Raw, wrpcap

pkts = []

inner_src = "10.20.0.1"
inner_dst = "10.20.0.2"

for i in range(20):
    inner = (
        IP(src=inner_src, dst=inner_dst, id=1000 + i)
        / TCP(
            sport=44444,
            dport=80,
            seq=1 + i,
            flags="PA",
        )
        / Raw(b"X")
    )

    if i % 2 == 0:
        pkt = Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02") / inner
    else:
        pkt = (
            Ether(src="02:00:00:00:00:03", dst="02:00:00:00:00:04")
            / IP(src="192.0.2.1", dst="198.51.100.1", id=2000 + i)
            / GRE(proto=0x0800)
            / inner
        )

    pkt.time = 1.0 + i * 0.001
    pkts.append(pkt)

wrpcap("tunnel-direct-bypass.pcap", pkts)
