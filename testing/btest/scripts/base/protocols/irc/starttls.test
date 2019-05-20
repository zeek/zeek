# @TEST-EXEC: zeek -b -C -r $TRACES/tls/irc-starttls.pcap %INPUT
# @TEST-EXEC: btest-diff conn.log
# @TEST-EXEC: btest-diff ssl.log
# @TEST-EXEC: btest-diff x509.log

@load base/protocols/conn
@load base/frameworks/dpd
@load base/protocols/ssl
@load base/protocols/irc
