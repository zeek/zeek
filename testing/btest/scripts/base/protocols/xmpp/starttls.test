# @TEST-EXEC: zeek -C -b -r $TRACES/tls/xmpp-starttls.pcap %INPUT
# @TEST-EXEC: btest-diff conn.log
# @TEST-EXEC: btest-diff ssl.log
# @TEST-EXEC: btest-diff x509.log

@load base/protocols/conn
@load base/frameworks/dpd
@load base/protocols/ssl
@load base/protocols/xmpp
