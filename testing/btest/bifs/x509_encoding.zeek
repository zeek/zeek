# @TEST-EXEC: zeek -b -r $TRACES/tls/tls12-encoding.pcap %INPUT >out
# @TEST-EXEC: btest-diff out

@load base/protocols/ssl

event x509_certificate(f: fa_file, cert_ref: opaque of x509, cert: X509::Certificate)
{
	print(fmt("serial: %s", cert$serial));
	print_raw(fmt("original issuer: %s\n", x509_get_issuer_original_name(cert_ref)));
	print_raw(fmt("original subject: %s\n", x509_get_subject_original_name(cert_ref)));
	print_raw(fmt("issuer: %s\n", cert$issuer));
	print_raw(fmt("subject: %s\n", cert$subject));
}
