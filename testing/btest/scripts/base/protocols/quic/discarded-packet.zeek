# @TEST-DOC: Test the QUIC::max_discarded_packet_events setting and its.

# @TEST-REQUIRES: ${SCRIPTS}/have-spicy

# @TEST-EXEC: zeek -r $TRACES/quic/quic-39264-rand.pcap base/protocols/quic QUIC::max_discarded_packet_events=-1
# @TEST-EXEC: test ! -f analyzer.log || cat analyzer.log >&2
# @TEST-EXEC: zeek-cut -m ts uid history service_name < quic.log > quic.log.no-discarded-packets

# @TEST-EXEC: zeek -r $TRACES/quic/quic-39264-rand.pcap base/protocols/quic QUIC::max_discarded_packet_events=1
# @TEST-EXEC: test ! -f analyzer.log || cat analyzer.log >&2
# @TEST-EXEC: zeek-cut -m ts uid history service_name < quic.log > quic.log.one-discarded-packet

# @TEST-EXEC: zeek -r $TRACES/quic/quic-39264-rand.pcap base/protocols/quic
# @TEST-EXEC: test ! -f analyzer.log || cat analyzer.log >&2
# @TEST-EXEC: zeek-cut -m ts uid history service_name < quic.log > quic.log.default-discarded-packets

# @TEST-EXEC: btest-diff quic.log.no-discarded-packets
# @TEST-EXEC: btest-diff quic.log.one-discarded-packet
# @TEST-EXEC: btest-diff quic.log.default-discarded-packets
