# @TEST-DOC: Tests the limit on the number of reassembler blocks
# @TEST-EXEC: zeek -C -r $TRACES/tcp/reassembly.pcap %INPUT
# @TEST-EXEC: btest-diff-cut -m weird.log
# @TEST-EXEC: btest-diff-cut -m conn.log

@load base/frameworks/notice/weird
@load base/protocols/conn

redef tcp_max_reassembler_blocks=2;
