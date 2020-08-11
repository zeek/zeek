# @TEST-EXEC: zeek -b -C -r $TRACES/tls/ecdsa-cert.pcap %INPUT
# @TEST-EXEC: btest-diff ssl.log
# @TEST-EXEC: btest-diff x509.log

@load base/protocols/ssl
@load base/files/x509
