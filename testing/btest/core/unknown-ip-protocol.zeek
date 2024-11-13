# @TEST-DOC: Tests that connections with unknown IP protocols are logged
# @TEST-EXEC: zeek -b -r $TRACES/communityid/sctp.pcap %INPUT
# @TEST-EXEC: btest-diff conn.log

@load base/protocols/conn
