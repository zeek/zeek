# @TEST-EXEC: zeek -b -C -r $TRACES/tls/google-cert-repeat.pcap common.zeek %INPUT
# @TEST-EXEC: btest-diff ssl.log
# @TEST-EXEC: btest-diff x509.log
# @TEST-EXEC: btest-diff .stdout

@TEST-START-FILE common.zeek

@load base/protocols/ssl
@load protocols/ssl/validate-certs.zeek

event x509_certificate(f: fa_file, cert_ref: opaque of x509, cert: X509::Certificate)
	{
	print "x509_certificate", cert$subject;
	}

hook SSL::ssl_finishing(c: connection)
	{
	print "finishing", c$ssl$cert_chain[0]$x509$certificate$subject;
	}

hook X509::x509_certificate_cache_replay(f: fa_file, e: X509::Info, sha256: string) &priority=5
	{
	print "Hook for", e$certificate$subject;
	}

@TEST-END-FILE

# First: Plain, no changes - certificate event caching won't even engage.

# @TEST-START-NEXT

# Second - engage certificate caching.
# Log files and events are unchanged - but the replay hook engages

redef X509::caching_required_encounters = 1;
redef X509::certificate_cache_minimum_eviction_interval = 11min;

# @TEST-START-NEXT

# Third - load policy script to not raise events
# Log files are unchanged; events are not raised from the third time.

redef X509::caching_required_encounters = 1;
redef X509::certificate_cache_minimum_eviction_interval = 11min;

@load policy/files/x509/disable-certificate-events-known-certs
