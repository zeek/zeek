# @TEST-DOC: Test that client initiating connection using 0RTT packet doesn't cause analyzer errors trying to decrypt server side.
#
# interop pcaps have link type DLT_PPP, test for its availability. Available in Zeek 6.1 or later only.
# @TEST-REQUIRES: zeek -b -e 'print PacketAnalyzer::ANALYZER_PPP ==  PacketAnalyzer::ANALYZER_PPP'
#
# @TEST-EXEC: zeek -Cr $TRACES/quic/interop/quic-go_quic-go/zerortt.pcap base/protocols/quic
# @TEST-EXEC: zeek-cut -m ts uid history service < conn.log > conn.log.cut
# @TEST-EXEC: btest-diff conn.log.cut
# @TEST-EXEC: btest-diff ssl.log
# @TEST-EXEC: btest-diff quic.log
# @TEST-EXEC: btest-diff .stderr
# @TEST-EXEC: test ! -f analyzer.log
