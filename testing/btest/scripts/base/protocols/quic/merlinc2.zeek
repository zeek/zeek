# @TEST-DOC: Test PCAP for Merlin C2 from issue #4198

# @TEST-REQUIRES: ${SCRIPTS}/have-spicy
# @TEST-EXEC: zeek -Cr $TRACES/quic/merlinc2_Zeek_example.pcapng base/protocols/quic
# @TEST-EXEC: zeek-cut -m ts uid history service < conn.log > conn.log.cut
# @TEST-EXEC: btest-diff conn.log.cut
# @TEST-EXEC: btest-diff ssl.log
# @TEST-EXEC: btest-diff quic.log
