# @TEST-DOC: Verify ClientHello extensions cannot exceed their declared byte length.
#
# @TEST-EXEC: zeek -b -C -r $TRACES/tls/client-hello-extension-length.pcap %INPUT >out
# @TEST-EXEC: btest-diff out
# @TEST-EXEC: btest-diff-cut -m weird.log

@load base/protocols/ssl
@load base/frameworks/notice/weird

global extension_count = 0;

event ssl_extension(c: connection, is_client: bool, code: count, val: string)
	{
	++extension_count;
	}

event zeek_done()
	{
	print "bounded", extension_count == 1;
	}
