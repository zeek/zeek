# @TEST-DOC: Tests an IPv6/UDP exchange encapsulated directly in Geneve.

# @TEST-EXEC: zeek -b -r $TRACES/tunnels/geneve-ipv6.pcap %INPUT
# @TEST-EXEC: btest-diff conn.log
# @TEST-EXEC: btest-diff tunnel.log

@load base/frameworks/tunnels
@load base/protocols/conn
