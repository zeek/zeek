# @TEST-EXEC: zeek -C -b -r $TRACES/tls/xmpp-starttls.pcap %INPUT
# @TEST-EXEC: btest-diff ssl.log

@load base/frameworks/dpd
@load base/frameworks/signatures
@load base/protocols/ssl
@load base/protocols/conn
@load-sigs base/protocols/xmpp/dpd.sig
