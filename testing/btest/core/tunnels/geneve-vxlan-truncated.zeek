# @TEST-DOC: Tests truncated packets tunneled via VXLAN inside GENEVE
# @TEST-EXEC: zeek -b -r $TRACES/tunnels/geneve-vxlan-dns-truncated.pcap %INPUT
# @TEST-EXEC: btest-diff conn.log
# @TEST-EXEC: btest-diff tunnel.log

@load base/frameworks/tunnels
@load base/protocols/conn
@load base/protocols/dns
