# @TEST-EXEC: zeek -b -Cr $TRACES/tunnels/geneve-truncated.pcap %INPUT
# @TEST-EXEC: btest-diff conn.log
# @TEST-EXEC: btest-diff weird.log
# @TEST-EXEC: test ! -e tunnel.log

@load base/frameworks/tunnels
@load base/protocols/conn
@load base/frameworks/notice/weird
