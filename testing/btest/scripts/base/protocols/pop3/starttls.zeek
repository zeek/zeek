# @TEST-EXEC: zeek -C -b -r $TRACES/tls/pop3-starttls.pcap %INPUT
# @TEST-EXEC: btest-diff conn.log
# @TEST-EXEC: btest-diff ssl.log
# @TEST-EXEC: btest-diff x509.log

@load base/protocols/conn
@load base/protocols/ssl
@load base/protocols/pop3
