# @TEST-DOC: Packets with bad checksums are analyzed and flagged by default, discarded with drop_bad_checksums=T, and not validated with -C.
#
# @TEST-EXEC: zeek -b -r $TRACES/chksums/localhost-bad-chksum.pcap %INPUT
# @TEST-EXEC: btest-diff-cut -m uid history orig_pkts resp_pkts conn_state conn.log
# @TEST-EXEC: btest-diff-cut -m uid name addl source weird.log
#
# @TEST-EXEC: zeek -b -r $TRACES/chksums/localhost-bad-chksum.pcap %INPUT drop_bad_checksums=T
# @TEST-EXEC: mv conn.log conn-drop.log && mv weird.log weird-drop.log
# @TEST-EXEC: btest-diff-cut -m uid history orig_pkts resp_pkts conn_state conn-drop.log
# @TEST-EXEC: btest-diff-cut -m uid name addl source weird-drop.log
#
# @TEST-EXEC: zeek -b -C -r $TRACES/chksums/localhost-bad-chksum.pcap %INPUT
# @TEST-EXEC: mv conn.log conn-ignore.log
# @TEST-EXEC: btest-diff-cut -m uid history orig_pkts resp_pkts conn_state conn-ignore.log
# @TEST-EXEC: test ! -f weird.log

@load base/protocols/conn
@load base/frameworks/notice/weird
