# Needs perftools support.
#
# @TEST-GROUP: leaks
#
# @TEST-REQUIRES: zeek  --help 2>&1 | grep -q mem-leaks
#
# @TEST-EXEC: HEAP_CHECK_DUMP_DIRECTORY=. HEAPCHECK=local btest-bg-run zeek zeek -b -m -r $TRACES/tls/ocsp-stapling.trace %INPUT
# @TEST-EXEC: btest-bg-wait 60

@load base/protocols/ssl

event ssl_stapled_ocsp(c: connection, is_orig: bool, response: string)
	{
	local chain: vector of opaque of x509 = vector();
	for ( i in c$ssl$cert_chain )
		chain[i] = c$ssl$cert_chain[i]$x509$handle;

	print x509_ocsp_verify(chain, response, SSL::root_certs);
	}
