##! This script is used to extract certificates seen on the wire to Zeek log files.
##! The certificates are base64-encoded and written to ssl.log, to the newly added cert
##! field.

@load base/protocols/ssl
@load base/files/x509

redef record X509::Info += {
	## Base64 encoded X.509 certificate.
	cert: string &log &optional;
};

event x509_certificate(f: fa_file, cert_ref: opaque of x509, cert: X509::Certificate) &priority=1
	{
	if ( ! f$info?$x509 )
		return;

	f$info$x509$cert = encode_base64(x509_get_certificate_string(cert_ref));
	}
