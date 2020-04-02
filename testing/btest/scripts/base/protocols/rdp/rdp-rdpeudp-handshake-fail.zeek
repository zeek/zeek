# @TEST-EXEC: zeek -r $TRACES/rdp/rdp-rdpeudp-handshake-fail.pcap %INPUT
# @TEST-EXEC: btest-diff conn.log

@load base/protocols/rdp

event rdpeudp_syn(c: connection) {
  print "rdpeudp_syn";
}

event rdpeudp_synack(c: connection) {
  print "rdpeudp_synack";
}

event rdpeudp_established(c: connection, version: count) {
  print "rdpeudp_established";
  print "version", version;
}

event rdpeudp_data(c: connection, is_orig: bool, version: count, data: string)
{
  print "rdpeudp_data";
  print fmt("is_orig: %s, version %d, data: %s", is_orig, version, data);
}
