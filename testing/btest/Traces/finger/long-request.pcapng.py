#!/usr/bin/env python3

from pathlib import Path

from scapy.all import IP, TCP, Ether, Raw, wrpcapng

OUTDIR = Path(__file__).resolve().parent
SRC = "10.0.0.1"
DST = "10.0.0.2"
SMAC = "02:00:00:00:00:01"
DMAC = "02:00:00:00:00:02"


def tcp_packet(
    src_addr,
    dst_addr,
    src_mac,
    dst_mac,
    src_port,
    dst_port,
    seq,
    ack,
    flags,
    payload=b"",
):
    packet = (
        Ether(src=src_mac, dst=dst_mac)
        / IP(src=src_addr, dst=dst_addr, id=0x1234, flags="DF", ttl=64)
        / TCP(
            sport=src_port, dport=dst_port, seq=seq, ack=ack, flags=flags, window=64240
        )
    )
    if payload:
        packet /= Raw(payload)
    return packet


def chunks(data, n=1200):
    return [data[i : i + n] for i in range(0, len(data), n)]


def tcp_flow(dst_port, payloads, src_port=40079):
    cseq, sseq = 1000, 8000
    packets = [
        tcp_packet(SRC, DST, SMAC, DMAC, src_port, dst_port, cseq, 0, "S"),
        tcp_packet(DST, SRC, DMAC, SMAC, dst_port, src_port, sseq, cseq + 1, "SA"),
        tcp_packet(SRC, DST, SMAC, DMAC, src_port, dst_port, cseq + 1, sseq + 1, "A"),
    ]
    seq = cseq + 1
    for payload in payloads:
        packets.append(
            tcp_packet(
                SRC, DST, SMAC, DMAC, src_port, dst_port, seq, sseq + 1, "PA", payload
            )
        )
        seq += len(payload)
    packets.append(
        tcp_packet(SRC, DST, SMAC, DMAC, src_port, dst_port, seq, sseq + 1, "FA")
    )
    packets.append(
        tcp_packet(DST, SRC, DMAC, SMAC, dst_port, src_port, sseq + 1, seq + 1, "FA")
    )
    return packets


def stamp(packets):
    for i, packet in enumerate(packets):
        packet.time = i / 1000000
    return packets


wrpcapng(
    str(OUTDIR / "long-request.pcapng"),
    stamp(tcp_flow(79, chunks(b"A" * 1300 + b"\r\n"))),
)
