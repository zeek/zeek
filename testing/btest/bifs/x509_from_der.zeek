# @TEST-DOC: x509_from_der() round-trips a valid certificate and reports an error instead of crashing on invalid input.
#
# @TEST-EXEC: zeek -b -r $TRACES/tls/tls-expired-cert.pcap %INPUT >out 2>&1
# @TEST-EXEC: btest-diff out

@load base/protocols/ssl

global done = F;

event x509_certificate(f: fa_file, cert_ref: opaque of x509, cert: X509::Certificate)
	{
	if ( done )
		return;

	done = T;
	local der = x509_get_certificate_string(cert_ref);
	local cert2 = x509_from_der(der);
	print "valid", x509_parse(cert2)$subject == cert$subject;
	}

event zeek_done()
	{
	local cert = x509_from_der("not a der certificate");
	print "unreachable", x509_parse(cert);
	}
