#!/usr/bin/env python3
"""Modbus register-memory-map (track-memmap) device-state growth trace.

Each flow is a complete Modbus/TCP connection from one client to a *unique*
slave address, issuing a read-holding-registers request/response spanning
``REGISTERS_PER_FLOW`` consecutive register addresses. Every new slave adds an
entry to the policy's ``device_registers`` table (driving its growth), and each
distinct address read from a slave adds an entry to that slave's per-device
register table. Pair it with a btest that redefs ``Modbus::max_device_registers``
and/or ``Modbus::max_slave_registers`` to small values to exercise the eviction
(``modbus_max_device_registers_exceeded`` / ``modbus_max_slave_registers_exceeded``)
paths without a huge trace.

Rewritten with global.anthropic.claude-opus-4-8 to use Scapy (AI assistance
disclosed per AI_POLICY.md).
"""

from pathlib import Path

from scapy.all import IP, TCP, Ether, Raw, wrpcap
from scapy.contrib.modbus import (
    ModbusADURequest,
    ModbusADUResponse,
    ModbusPDU03ReadHoldingRegistersRequest,
    ModbusPDU03ReadHoldingRegistersResponse,
)

CLIENT = "10.0.0.1"
CLIENT_PORT = 40000
SERVER_PORT = 502
# Unique slave address per flow, starting here and incrementing (10.1.0.1, ...).
FIRST_SERVER = 0x0A010001
# Enough distinct slaves to overflow a modestly-redefed max_device_registers.
FLOW_COUNT = 20
# Consecutive register addresses read per slave; enough distinct addresses to
# overflow a modestly-redefed max_slave_registers.
REGISTERS_PER_FLOW = 20
BASE_TIME = 1_700_000_000.0

CLIENT_MAC = "02:00:00:00:00:01"
SERVER_MAC = "02:00:00:00:00:02"


def _slave_addr(index):
    octets = (FIRST_SERVER + index).to_bytes(4, "big")
    return ".".join(str(b) for b in octets)


def pkt(server, is_orig, seq, ack, flags, payload=b""):
    if is_orig:
        src, dst, sport, dport = CLIENT, server, CLIENT_PORT, SERVER_PORT
        eth_src, eth_dst = CLIENT_MAC, SERVER_MAC
    else:
        src, dst, sport, dport = server, CLIENT, SERVER_PORT, CLIENT_PORT
        eth_src, eth_dst = SERVER_MAC, CLIENT_MAC
    p = (
        Ether(src=eth_src, dst=eth_dst)
        / IP(src=src, dst=dst)
        / TCP(sport=sport, dport=dport, seq=seq, ack=ack, flags=flags)
    )
    if payload:
        p = p / Raw(payload)
    return p


def build_flow(index):
    """One full Modbus/TCP connection to a unique slave: handshake, read, close."""
    server = _slave_addr(index)

    request = bytes(
        ModbusADURequest(transId=index & 0xFFFF, unitId=1)
        / ModbusPDU03ReadHoldingRegistersRequest(
            startAddr=0, quantity=REGISTERS_PER_FLOW
        )
    )
    response = bytes(
        ModbusADUResponse(transId=index & 0xFFFF, unitId=1)
        / ModbusPDU03ReadHoldingRegistersResponse(
            registerVal=[
                (index + offset) & 0xFFFF for offset in range(REGISTERS_PER_FLOW)
            ]
        )
    )

    client_seq, server_seq = 1000, 5000
    packets = [
        pkt(server, True, client_seq, 0, "S"),
        pkt(server, False, server_seq, client_seq + 1, "SA"),
        pkt(server, True, client_seq + 1, server_seq + 1, "A"),
    ]
    client_seq += 1
    server_seq += 1

    packets.append(pkt(server, True, client_seq, server_seq, "PA", request))
    client_seq += len(request)
    packets.append(pkt(server, False, server_seq, client_seq, "PA", response))
    server_seq += len(response)

    # Client ACKs the response, then a clean FIN/ACK teardown (FIN consumes a seq).
    packets.append(pkt(server, True, client_seq, server_seq, "A"))
    packets.append(pkt(server, True, client_seq, server_seq, "FA"))
    client_seq += 1
    packets.append(pkt(server, False, server_seq, client_seq, "FA"))
    server_seq += 1
    packets.append(pkt(server, True, client_seq, server_seq, "A"))
    return packets


def build_packets():
    packets = []
    for index in range(FLOW_COUNT):
        packets.extend(build_flow(index))
    return packets


def main():
    packets = build_packets()

    for index, p in enumerate(packets):
        p.time = BASE_TIME + index * 0.001

    wrpcap(str(Path(__file__).with_suffix("")), packets)


if __name__ == "__main__":
    main()
