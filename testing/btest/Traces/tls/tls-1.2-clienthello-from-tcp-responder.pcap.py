#!/usr/bin/env python3

"""Generate a TLS 1.2 trace with reversed TCP and TLS application roles.

The TCP responder acts as the TLS client and sends the ClientHello, while the
TCP originator acts as the TLS server and sends the ServerHello. This exercises
TLS DPD when the application roles differ from the TCP roles.

Generated with OpenAI GPT-5.6
"""

from pathlib import Path

from scapy.all import IP, TCP, Ether, wrpcap
from scapy.layers.tls.handshake import TLSClientHello, TLSServerHello
from scapy.layers.tls.record import TLS


ORIG_MAC = "02:00:00:00:00:10"
RESP_MAC = "02:00:00:00:00:20"

ORIG_IP = "192.0.2.10"
RESP_IP = "192.0.2.20"

ORIG_PORT = 41000
RESP_PORT = 31338

ORIG_ISN = 1000
RESP_ISN = 5000

OUTPUT = Path(__file__).with_suffix("")
BASE_TIMESTAMP = 1.0
TIMESTAMP_STEP = 0.001


def make_client_hello():
    return TLS(
        type=22,
        version=0x0301,
        msg=[
            TLSClientHello(
                version=0x0303,
                gmt_unix_time=0x00010203,
                random_bytes=bytes(range(0x04, 0x20)),
                sid=b"",
                ciphers=[0x002F],
                comp=[0],
                ext=[],
            )
        ],
    )


def make_server_hello():
    return TLS(
        type=22,
        version=0x0303,
        msg=[
            TLSServerHello(
                version=0x0303,
                gmt_unix_time=0x20212223,
                random_bytes=bytes(range(0x24, 0x40)),
                sid=b"",
                cipher=0x002F,
                comp=[0],
                ext=[],
            )
        ],
    )


class FlowBuilder:
    def __init__(self):
        self.packets = []
        self.orig_seq = ORIG_ISN
        self.resp_seq = RESP_ISN
        self.timestamp = BASE_TIMESTAMP

    def _packet(self, from_orig, flags, payload=None):
        if from_orig:
            src_mac, dst_mac = ORIG_MAC, RESP_MAC
            src_ip, dst_ip = ORIG_IP, RESP_IP
            sport, dport = ORIG_PORT, RESP_PORT
            seq = self.orig_seq
            ack = self.resp_seq if "A" in flags else 0
        else:
            src_mac, dst_mac = RESP_MAC, ORIG_MAC
            src_ip, dst_ip = RESP_IP, ORIG_IP
            sport, dport = RESP_PORT, ORIG_PORT
            seq = self.resp_seq
            ack = self.orig_seq if "A" in flags else 0

        packet = (
            Ether(src=src_mac, dst=dst_mac)
            / IP(src=src_ip, dst=dst_ip, id=0)
            / TCP(sport=sport, dport=dport, seq=seq, ack=ack, flags=flags)
        )

        if payload is not None:
            packet /= payload

        packet.time = self.timestamp
        self.timestamp += TIMESTAMP_STEP
        self.packets.append(packet)

    def send_orig(self, flags, payload=None):
        self._packet(True, flags, payload)
        self.orig_seq += self._consumed(flags, payload)

    def send_resp(self, flags, payload=None):
        self._packet(False, flags, payload)
        self.resp_seq += self._consumed(flags, payload)

    @staticmethod
    def _consumed(flags, payload):
        payload_length = len(bytes(payload)) if payload is not None else 0
        return payload_length + (1 if "S" in flags or "F" in flags else 0)


def build_packets():
    flow = FlowBuilder()

    # Normal TCP three-way handshake.
    flow.send_orig("S")
    flow.send_resp("SA")
    flow.send_orig("A")

    # The TCP responder is the TLS client and initiates the TLS handshake.
    flow.send_resp("PA", make_client_hello())
    flow.send_orig("A")
    flow.send_orig("PA", make_server_hello())
    flow.send_resp("A")

    # Clean TCP shutdown.
    flow.send_resp("FA")
    flow.send_orig("FA")
    flow.send_resp("A")

    return flow.packets


def main():
    packets = build_packets()
    wrpcap(str(OUTPUT), packets)
    print(f"Wrote {len(packets)} packets to {OUTPUT}")


if __name__ == "__main__":
    main()
