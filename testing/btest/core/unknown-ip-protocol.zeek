# @TEST-DOC: Tests that connections with unknown IP protocols are logged
# @TEST-EXEC: zeek -b -r $TRACES/communityid/sctp.pcap %INPUT
# @TEST-EXEC: btest-diff conn.log
# @TEST-EXEC: btest-diff-cut -m unknown_protocols.log

@load misc/unknown-protocols

@load base/protocols/conn

redef record UnknownProtocol::Info$protocol_id_num += { &log };
