# Test that certificate event caching works as expected.

# @TEST-EXEC: zeek -b -r $TRACES/tls/google-duplicate.trace %INPUT
# @TEST-EXEC: btest-diff x509.log
# @TEST-EXEC: btest-diff .stdout

@load base/protocols/ssl

redef X509::caching_required_encounters = 1;

redef X509::relog_known_certificates_after = 0secs;

hook X509::x509_certificate_cache_replay(f: fa_file, e: any, sha256: string) &priority=1
	{
	print "Encountered cached certificate not further handled by core", sha256;
	}
