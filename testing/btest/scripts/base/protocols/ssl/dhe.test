# @TEST-EXEC: zeek -b -r $TRACES/tls/dhe.pcap %INPUT
# @TEST-EXEC: btest-diff .stdout
# @TEST-EXEC: btest-diff ssl.log

@load base/protocols/ssl

event ssl_dh_server_params(c: connection, p: string, q: string, Ys: string)
  {
  print "key length in bits", |Ys|*8;
  }
