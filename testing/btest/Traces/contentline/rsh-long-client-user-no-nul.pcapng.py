#!/usr/bin/env python3

from pathlib import Path

from scapy.all import IP, TCP, Ether, Raw, wrpcapng

OUTDIR = Path(__file__).resolve().parent
SRC = "10.0.0.1"
DST = "10.0.0.2"
SMAC = "02:00:00:00:00:01"
DMAC = "02:00:00:00:00:02"


def pkt(src_ip, dst_ip, sport, dport, seq, ack, flags, payload=b""):
    p = (
        Ether(src=SMAC, dst=DMAC)
        / IP(src=src_ip, dst=dst_ip, id=0x1234, flags="DF", ttl=64)
        / TCP(sport=sport, dport=dport, seq=seq, ack=ack, flags=flags, window=64240)
    )
    if payload:
        p = p / Raw(load=payload)
    return p


def chunks(data, n=1200):
    return [data[i : i + n] for i in range(0, len(data), n)]


def tcp_flow(dst_port, payloads, src_port=40000):
    cseq, sseq = 1000, 8000
    packets = [
        pkt(SRC, DST, src_port, dst_port, cseq, 0, "S"),
        pkt(DST, SRC, dst_port, src_port, sseq, cseq + 1, "SA"),
        pkt(SRC, DST, src_port, dst_port, cseq + 1, sseq + 1, "A"),
    ]
    seq = cseq + 1
    for payload in payloads:
        packets.append(pkt(SRC, DST, src_port, dst_port, seq, sseq + 1, "PA", payload))
        seq += len(payload)
    packets.append(pkt(SRC, DST, src_port, dst_port, seq, sseq + 1, "FA"))
    packets.append(pkt(DST, SRC, dst_port, src_port, sseq + 1, seq + 1, "FA"))
    return packets


payload = b"0\x00" + b"client_user_" * 1398100  # Roughly 16 * 1024 * 1024 / 12
wrpcapng(
    str(OUTDIR / "rsh-long-client-user-no-nul.pcapng"),
    tcp_flow(514, chunks(payload), 40002),
)
