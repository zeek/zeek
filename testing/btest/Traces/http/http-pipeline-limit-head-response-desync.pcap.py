#!/usr/bin/env python3
"""HTTP pipelining limit clears the pending-request queue ahead of a HEAD.

The client pipelines exactly HTTP::max_pending_requests (10) GET requests
followed by a single HEAD request, and only then does the server start
answering. Reaching the pending-request limit on the 10th GET clears Zeek's
unanswered_requests queue, so the trailing HEAD would otherwise become the
sole pending method: when the first GET response arrived, ExpectReplyMessageBody()
would see "HEAD" at the front of the queue and treat the response as bodyless,
so the GET response body would be parsed as the next reply line and raise an
analyzer violation ("not a http reply line").

To avoid that misparse, the analyzer disables responder-side deliveries when it
clears the queue (content_line_resp->SetSkipDeliveries(true) in HTTP.cc): once
request/response correlation is lost, no further replies are parsed, so no bogus
violation is raised. Requests keep parsing (all 15 appear in http.log); the
responses are simply left uncorrelated.

After the pipelined burst the connection continues strictly non-pipelined: four
more HEAD requests are each fully answered before the next is sent (five HEAD
requests in total: one pipelined, four non-pipelined), exercising the tail once
the limit has been hit.

The trace is well-formed on the wire (a real dissector accepts every packet).

Generated with Claude Opus 4.8 using Scapy.
"""

from pathlib import Path

from scapy.all import IP, TCP, Ether, Raw, wrpcap

CLIENT = "192.0.2.1"
SERVER = "192.0.2.2"
CLIENT_PORT = 40000
SERVER_PORT = 80
BASE_TIME = 1_700_000_000.0

# Must match HTTP::max_pending_requests in the accompanying test: the 10th GET
# is what reaches the limit and clears the pending-request queue.
GET_COUNT = 10

# HEAD requests sent after the pipelined burst, each answered before the next
# is sent (strictly non-pipelined). Plus the one pipelined HEAD, that is five
# HEAD requests in total.
HEAD_FOLLOWUP_COUNT = 4


def pkt(is_orig, seq, ack, flags, payload=b""):
    if is_orig:
        src, dst, sport, dport = CLIENT, SERVER, CLIENT_PORT, SERVER_PORT
        eth_src, eth_dst = "02:00:00:00:00:01", "02:00:00:00:00:02"
    else:
        src, dst, sport, dport = SERVER, CLIENT, SERVER_PORT, CLIENT_PORT
        eth_src, eth_dst = "02:00:00:00:00:02", "02:00:00:00:00:01"
    p = (
        Ether(src=eth_src, dst=eth_dst)
        / IP(src=src, dst=dst)
        / TCP(sport=sport, dport=dport, seq=seq, ack=ack, flags=flags)
    )
    if payload:
        p = p / Raw(payload)
    return p


def request(method, path):
    return (
        f"{method} {path} HTTP/1.1\r\n".encode() + b"Host: server.example\r\n" + b"\r\n"
    )


def get_response(body):
    return (
        b"HTTP/1.1 200 OK\r\n"
        + f"Content-Length: {len(body)}\r\n".encode()
        + b"\r\n"
        + body
    )


def head_response():
    return b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"


def build_packets():
    client_seq, server_seq = 1001, 2001  # post-SYN sequence numbers

    packets = [
        pkt(True, 1000, 0, "S"),
        pkt(False, 2000, 1001, "SA"),
        pkt(True, client_seq, server_seq, "A"),
    ]

    def client_send(payload):
        nonlocal client_seq
        packets.append(pkt(True, client_seq, server_seq, "PA", payload))
        client_seq += len(payload)

    def server_send(payload):
        nonlocal server_seq
        packets.append(pkt(False, server_seq, client_seq, "PA", payload))
        server_seq += len(payload)

    # Phase A -- pipelined burst: 10 GETs then 1 HEAD, all sent before any
    # response. The 10th GET reaches HTTP::max_pending_requests and clears the
    # pending-request queue, leaving the trailing HEAD as the sole pending
    # method.
    for i in range(GET_COUNT):
        client_send(request("GET", f"/{i}"))
    client_send(request("HEAD", "/head-0"))

    # Server answers the whole burst in order: 10 GET responses (each with a
    # body) then the HEAD response. Because responder deliveries are skipped
    # once the queue is cleared, none of these are parsed; pre-fix, the first
    # GET response body was misparsed as a bodyless HEAD response and tripped
    # the analyzer violation.
    for i in range(GET_COUNT):
        server_send(get_response(f"body-of-response-{i}\r\n".encode()))
    server_send(head_response())

    # Phase B -- strictly non-pipelined: four further HEAD requests, each fully
    # answered before the next is sent, so request/response correlation is
    # unambiguous and stays in sync.
    for i in range(1, HEAD_FOLLOWUP_COUNT + 1):
        client_send(request("HEAD", f"/head-{i}"))
        server_send(head_response())

    # Client acknowledges the final response before closing so no server bytes
    # are left unacknowledged at teardown.
    packets.append(pkt(True, client_seq, server_seq, "A"))

    # FIN/ACK teardown, client-initiated (a FIN consumes one seq).
    packets.append(pkt(True, client_seq, server_seq, "FA"))
    client_seq += 1
    packets.append(pkt(False, server_seq, client_seq, "FA"))
    server_seq += 1
    packets.append(pkt(True, client_seq, server_seq, "A"))

    return packets


def main():
    packets = build_packets()

    # Assign reproducible, monotonically increasing timestamps.
    for index, p in enumerate(packets):
        p.time = BASE_TIME + index * 0.001

    wrpcap(str(Path(__file__).with_suffix("")), packets)


if __name__ == "__main__":
    main()
