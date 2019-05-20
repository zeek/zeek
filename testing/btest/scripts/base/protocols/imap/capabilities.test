# @TEST-EXEC: zeek -b -C -r $TRACES/tls/imap-starttls.pcap %INPUT
# @TEST-EXEC: btest-diff .stdout

@load base/protocols/ssl
@load base/protocols/conn
@load base/frameworks/dpd
@load base/protocols/imap

event imap_capabilities(c: connection, capabilities: string_vec)
	{
	print capabilities;
	}
