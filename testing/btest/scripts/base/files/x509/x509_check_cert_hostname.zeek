# Test that certificate event caching works as expected.

# @TEST-EXEC: zeek -b -r $TRACES/tls/google-duplicate.trace common.zeek google-duplicate.zeek
# @TEST-EXEC: cat $TRACES/tls/tls-fragmented-handshake.pcap.gz | gunzip | zeek -b -r - common.zeek fragmented.zeek
# @TEST-EXEC: zeek -b -r $TRACES/rdp/rdp-to-ssl.pcap common.zeek rdp.zeek
# @TEST-EXEC: btest-diff .stdout

@TEST-START-FILE common.zeek

@load base/protocols/ssl

function test_it(cert_ref: opaque of x509, name: string, subject: string)
	{
	print subject, name, x509_check_cert_hostname(cert_ref, name);
	}

@TEST-END-FILE

@TEST-START-FILE google-duplicate.zeek

event x509_certificate(f: fa_file, cert_ref: opaque of x509, cert: X509::Certificate)
	{
	test_it(cert_ref, "www.google.com", cert$subject);
	test_it(cert_ref, "www.zeek.org", cert$subject);
	test_it(cert_ref, "hello.android.com", cert$subject);
	test_it(cert_ref, "g.co", cert$subject);
	test_it(cert_ref, "Google Internet Authority G2", cert$subject);
	}

@TEST-END-FILE

@TEST-START-FILE fragmented.zeek

event x509_certificate(f: fa_file, cert_ref: opaque of x509, cert: X509::Certificate)
	{
	test_it(cert_ref, "Bro", cert$subject);
	test_it(cert_ref, "Broo", cert$subject);
	test_it(cert_ref, "www.zeek.org", cert$subject);
	test_it(cert_ref, "9566.alt.helloIamADomain.example", cert$subject);
	}

@TEST-END-FILE

@TEST-START-FILE rdp.zeek

@load base/protocols/rdp

event x509_certificate(f: fa_file, cert_ref: opaque of x509, cert: X509::Certificate)
	{
	test_it(cert_ref, "WIN2K8R2.awakecoding.ath.cx", cert$subject);
	test_it(cert_ref, "awakecoding.ath.cx", cert$subject);
	test_it(cert_ref, "www.zeek.org", cert$subject);
	}

@TEST-END-FILE
