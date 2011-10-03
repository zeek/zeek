##! This script calculates MD5 sums for server DER formatted certificates.

@load base/protocols/ssl

module SSL;

export {
	redef record Info += {
		cert_hash: string &log &optional;
	};
}

event x509_certificate(c: connection, cert: X509, is_server: bool, chain_idx: count, chain_len: count, der_cert: string) &priority=10
	{
	# We aren't tracking client certificates yet and we are also only tracking
	# the primary cert.
	if ( ! is_server || chain_idx != 0 ) 
		return;

	c$ssl$cert_hash = md5_hash(der_cert);
	}