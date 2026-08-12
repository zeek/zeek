#!/usr/bin/env python3
"""
Generate irc-zip-bomb.pcap: an IRC server-to-server link that negotiates ZIP
compression, then carries a zlib stream that inflates to far more than it weighs
on the wire.

This exercises ZIP_Analyzer (src/analyzer/protocol/zip) via the IRC path. The
analyzer only attaches after both directions complete the S2S handshake: a PASS
command whose flags token contains 'Z', followed by a prefix-less SERVER command,
reaching REGISTERED + ACCEPT_ZIP on both sides (see IRC_Analyzer::DeliverStream).
Only then is the responder's subsequent stream treated as compressed. The
compressed payload here is highly repetitive, so a tiny on-wire blob decompresses
to many IRC lines, giving out >> in without a large PCAP. Set
IRC::max_uncompressed_size below the decompressed size in the test to trip
zip_inflate_output_size_exceeded.

Generated with Claude Opus 4.8 (Anthropic).
"""

import argparse
import zlib
from pathlib import Path

from scapy.all import IP, TCP, Ether, wrpcap

CLIENT_IP = "10.0.0.1"  # linking server (orig)
SERVER_IP = "10.0.0.2"  # hub server (resp)
CLIENT_PORT = 54321
SERVER_PORT = 6667

# Number of repeated IRC lines in the decompressed payload. Repetitive, so the
# on-wire zlib blob stays tiny while the inflated output is large.
LINE_COUNT = 100000


def pkt(src_ip, dst_ip, sport, dport, flags, seq, ack, payload=b""):
    return (
        Ether(src="00:00:00:00:00:01", dst="00:00:00:00:00:02")
        / IP(src=src_ip, dst=dst_ip)
        / TCP(sport=sport, dport=dport, flags=flags, seq=seq, ack=ack)
        / payload
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--line-count",
        type=int,
        default=LINE_COUNT,
        help="repeated IRC lines in the decompressed payload (default: %(default)s)",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path(__file__).with_suffix(""),
        help="output pcap path (default: derived from this script's name)",
    )
    args = parser.parse_args()

    c_seq = 1000
    s_seq = 2000
    pkts = []

    def cpkt(flags, payload=b""):
        nonlocal c_seq
        p = pkt(
            CLIENT_IP, SERVER_IP, CLIENT_PORT, SERVER_PORT, flags, c_seq, s_seq, payload
        )
        c_seq += len(payload)
        return p

    def spkt(flags, payload=b""):
        nonlocal s_seq
        p = pkt(
            SERVER_IP, CLIENT_IP, SERVER_PORT, CLIENT_PORT, flags, s_seq, c_seq, payload
        )
        s_seq += len(payload)
        return p

    # Three-way handshake (SYN/SYN-ACK consume one sequence number each).
    pkts.append(cpkt("S"))
    c_seq += 1
    pkts.append(spkt("SA"))
    s_seq += 1
    pkts.append(cpkt("A"))

    # S2S registration, both directions. The 'Z' flag in the PASS options token
    # is what makes each side ACCEPT_ZIP; the prefix-less SERVER marks REGISTERED.
    orig_reg = b"PASS linkpass 0210 IRC Z\r\nSERVER orig.example.org 1 :orig\r\n"
    resp_reg = b"PASS linkpass 0210 IRC Z\r\nSERVER hub.example.org 1 :hub\r\n"

    pkts.append(cpkt("PA", orig_reg))
    pkts.append(spkt("A"))
    pkts.append(spkt("PA", resp_reg))
    pkts.append(cpkt("A"))

    # After the responder's SERVER line is processed, ZIP_Analyzer attaches to
    # both directions. Everything the responder sends from here is compressed.
    #
    # IMPORTANT: the IRC analyzer adds ContentLine_Analyzer ahead of ZIP_Analyzer
    # in the support chain (see IRC_Analyzer's ctor vs. where ZIP is added), so
    # ContentLine strips CR (0x0d) / LF (0x0a) bytes out of the *compressed* blob
    # before ZIP sees it. If the compressed blob contains any 0x0d/0x0a, the zlib
    # stream is corrupted and inflate fails (inflate_failed) instead of tripping
    # the size limit. This exact payload compresses to a blob with no 0x0d/0x0a
    # bytes, so it inflates cleanly and reaches ForwardDecompressed.
    #
    # The committed pcap is a frozen artifact, so the test itself is not affected
    # by the local zlib version. But REGENERATING here with a different zlib (or a
    # different line/level) may produce a blob that contains a terminator byte;
    # the assert below fails loudly in that case so a bad pcap is never written.
    line = b":hub.example.org PING :flood\r\n"  # 30 bytes incl. CRLF
    assert len(line) == 30, len(line)
    decompressed = line * args.line_count
    blob = zlib.compress(decompressed, 9)
    assert b"\r" not in blob and b"\n" not in blob, (
        "compressed blob has a terminator byte"
    )

    pkts.append(spkt("PA", blob))
    pkts.append(cpkt("A"))

    # Teardown.
    pkts.append(spkt("FA"))
    s_seq += 1
    pkts.append(cpkt("FA"))
    c_seq += 1
    pkts.append(spkt("A"))

    wrpcap(str(args.output), pkts)
    print(
        f"Wrote {len(pkts)} packets to {args.output} "
        f"(blob {len(blob)} B on wire -> {len(decompressed)} B decompressed)"
    )


if __name__ == "__main__":
    main()
