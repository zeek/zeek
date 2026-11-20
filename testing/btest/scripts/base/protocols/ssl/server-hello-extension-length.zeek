# @TEST-DOC: Verify ServerHello extensions cannot exceed their declared byte length.
# @TEST-REQUIRES: ! have-spicy-ssl # Binpac analyzer uses weirds to keep parsing
#
# @TEST-EXEC: zeek -b -C -r $TRACES/tls/server-hello-extension-length.pcap %INPUT >out
# @TEST-EXEC: btest-diff out
# @TEST-EXEC: btest-diff-cut -m weird.log

@load base/protocols/ssl
@load base/frameworks/notice/weird

global extension_count = 0;

event ssl_extension(c: connection, is_client: bool, code: count, val: string)
	{
	if ( ! is_client )
		++extension_count;
	}

event zeek_done()
	{
	print "bounded", extension_count == 1;
	}
