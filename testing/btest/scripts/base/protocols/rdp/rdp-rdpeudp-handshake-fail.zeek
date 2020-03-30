# @TEST-EXEC: zeek -r $TRACES/rdp/rdp-rdpeudp-handshake-fail.pcap %INPUT
# @TEST-EXEC: btest-diff conn.log

@load base/protocols/rdp
