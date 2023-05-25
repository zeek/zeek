# @TEST-DOC: Tests a pcap containing a packet of size 14196 bytes with GENEVE encapsulation. Regression test for #2683.
# @TEST-EXEC: zeek -C -b -r $TRACES/tunnels/geneve-47101.pcap %INPUT
# @TEST-EXEC: btest-diff conn.log
# @TEST-EXEC: btest-diff tunnel.log

@load base/frameworks/tunnels
@load base/protocols/conn
@load base/protocols/ssl
