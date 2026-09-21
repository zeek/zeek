"""
Generate SMTP flows that amplify MIME folded-header state.

Each flow completes an SMTP dialog up to DATA and then sends a single header
("A:") folded across FOLD_COUNT continuation lines (" a"), followed by a second
header and the blank line terminating the header block. Every continuation line
is buffered as a separate line object for the one header, so the retained state
grows with FOLD_COUNT and is amplified across FLOW_COUNT concurrent flows.

Generated with OpenAI Codex, adapted to use Scapy and gzip compress by default
with the help of Clause Opus 4.8.
"""

import gzip

from scapy.all import IP, TCP, Ether, Raw, wrpcap

CLIENT = "192.0.2.1"
SERVER = "192.0.2.2"
SERVER_PORT = 25
FIRST_CLIENT_PORT = 40000
FOLD_COUNT = 10000
FLOW_COUNT = 5
SEGMENT_SIZE = 1400
ACK_INTERVAL = 32
BASE_TIME = 1700000000.0

SMTP_DIALOG = (
    (True, b"220 ready\r\n"),
    (False, b"EHLO local\r\n"),
    (True, b"250 ready\r\n"),
    (False, b"MAIL FROM:<a@example.test>\r\n"),
    (True, b"250 ok\r\n"),
    (False, b"RCPT TO:<b@example.test>\r\n"),
    (True, b"250 ok\r\n"),
    (False, b"DATA\r\n"),
    (True, b"354 continue\r\n"),
)


def pkt(server_to_client, client_port, seq, ack, flags, payload=b"", ts=0.0):
    if server_to_client:
        src, dst, sport, dport = SERVER, CLIENT, SERVER_PORT, client_port
    else:
        src, dst, sport, dport = CLIENT, SERVER, client_port, SERVER_PORT
    p = (
        Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")
        / IP(src=src, dst=dst)
        / TCP(sport=sport, dport=dport, seq=seq, ack=ack, flags=flags)
    )
    if payload:
        p = p / Raw(payload)
    p.time = BASE_TIME + ts
    return p


def flow_packets(client_port, message, ts):
    """Yield one established SMTP flow containing an unfinished header."""
    cseq, sseq = 1000, 2000

    def emit(server_to_client, payload, flags="PA"):
        nonlocal cseq, sseq, ts
        seq = sseq if server_to_client else cseq
        ack = cseq if server_to_client else sseq
        p = pkt(server_to_client, client_port, seq, ack, flags, payload, ts)
        ts += 0.001
        grow = len(payload) + (1 if "S" in flags else 0)
        if server_to_client:
            sseq += grow
        else:
            cseq += grow
        return p

    # Three-way handshake.
    yield emit(False, b"", "S")
    yield emit(True, b"", "SA")
    yield emit(False, b"", "A")

    for server_to_client, payload in SMTP_DIALOG:
        yield emit(server_to_client, payload)

    # Send the unfinished, heavily folded header in MSS-sized segments with
    # periodic ACKs from the server.
    for index, start in enumerate(range(0, len(message), SEGMENT_SIZE), start=1):
        yield emit(False, message[start : start + SEGMENT_SIZE])
        if index % ACK_INTERVAL == 0:
            yield emit(True, b"", "A")


def main():
    message = b"A:\r\n" + (b" a\r\n" * FOLD_COUNT) + b"B: other header\r\n\r\n"
    packets = []
    for flow in range(FLOW_COUNT):
        packets.extend(flow_packets(FIRST_CLIENT_PORT + flow, message, ts=flow * 100.0))

    with gzip.GzipFile(
        "mime-folded-header-state-memory-exhaustion.pcap.gz", "wb", mtime=0
    ) as f:
        wrpcap(f, packets)


if __name__ == "__main__":
    main()
