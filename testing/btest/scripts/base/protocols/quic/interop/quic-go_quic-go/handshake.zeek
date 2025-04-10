# @TEST-DOC: Test interop pcap containing RETRY packet from server side.

# @TEST-REQUIRES: ${SCRIPTS}/have-spicy
# @TEST-EXEC: zeek -Cr $TRACES/quic/interop/quic-go_quic-go/handshake.pcap base/protocols/quic
# @TEST-EXEC: zeek-cut -m ts uid history service < conn.log > conn.log.cut
# @TEST-EXEC: btest-diff conn.log.cut
# @TEST-EXEC: btest-diff ssl.log
# @TEST-EXEC: btest-diff quic.log
# @TEST-EXEC: btest-diff .stderr
# @TEST-EXEC: test ! -f analyzer_failed.log
