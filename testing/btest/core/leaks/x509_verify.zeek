# Needs perftools support.
#
# @TEST-GROUP: leaks
#
# @TEST-REQUIRES: zeek  --help 2>&1 | grep -q mem-leaks
#
# @TEST-EXEC: HEAP_CHECK_DUMP_DIRECTORY=. HEAPCHECK=local btest-bg-run zeek zeek -b -m -r $TRACES/tls/tls-expired-cert.trace %INPUT
# @TEST-EXEC: btest-bg-wait 60

@load base/protocols/ssl

event ssl_established(c: connection) &priority=3
	{
	local chain: vector of opaque of x509 = vector();
	for ( i in c$ssl$cert_chain )
		{
		chain[i] = c$ssl$cert_chain[i]$x509$handle;
		}

	local result = x509_verify(chain, SSL::root_certs);
	print fmt("Validation result: %s", result$result_string);
	if ( result$result != 0 ) # not ok
		return;

	print "Resulting chain:";
	for ( i in result$chain_certs )
		{
		local cert = result$chain_certs[i];
		local certinfo = x509_parse(cert);
		local sha1 = sha1_hash(x509_get_certificate_string(cert));
		print fmt("Fingerprint: %s, Subject: %s", sha1, certinfo$subject);
		}
	}
