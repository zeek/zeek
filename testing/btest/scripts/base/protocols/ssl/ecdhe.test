# @TEST-EXEC: zeek -b -r $TRACES/tls/ecdhe.pcap %INPUT
# @TEST-EXEC: btest-diff ssl.log
# @TEST-EXEC: btest-diff x509.log

@load base/protocols/ssl
@load base/files/x509
