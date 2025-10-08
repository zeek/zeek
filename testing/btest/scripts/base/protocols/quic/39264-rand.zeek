# @TEST-DOC: Regression test for #4847, QUIC packets with fixed_bit 0 are discarded.

# @TEST-REQUIRES: ${SCRIPTS}/have-spicy
# @TEST-EXEC: zeek -r $TRACES/quic/quic-39264-rand.pcap base/protocols/quic
# @TEST-EXEC: test ! -f analyzer.log || cat analyzer.log >&2
# @TEST-EXEC: zeek-cut -m ts uid history service < conn.log > conn.log.cut
# @TEST-EXEC: btest-diff conn.log.cut
# @TEST-EXEC: btest-diff ssl.log
# @TEST-EXEC: btest-diff quic.log
