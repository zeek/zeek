event rdpeudp_syn(c: connection) {
  print "scriptland: rdpeudp_syn event";
}

event rdpeudp_synack(c: connection) {
  print "scriptland: rdpeudp_synack event";
}

event rdpeudp_established(c: connection) {
  print "scriptland: rdpeudp_established event";
}

event rdpeudp_data(c: connection, is_orig:bool, data: string) {
  print fmt("scriptland: rdpeudp_data event, is_orig: %s, data: %s", is_orig, data);
}
