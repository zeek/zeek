##! Calculate MD5 sums for server DER formatted certificates.

@load base/protocols/ssl

module SSL;

export {
	redef record Info += {
		## MD5 sum of the raw server certificate.
		cert_hash: string &log &optional;
	};
}

event x509_certificate(c: connection, is_orig: bool, cert: X509, chain_idx: count, chain_len: count, der_cert: string) &priority=4
	{
	# We aren't tracking client certificates yet and we are also only tracking
	# the primary cert.  Watch that this came from an SSL analyzed session too.
	if ( is_orig || chain_idx != 0 || ! c?$ssl ) 
		return;

	c$ssl$cert_hash = md5_hash(der_cert);
	}