##! Performs various SSL certificate checks.

@load base/frameworks/notice
@load base/protocols/ssl
@load protocols/ssl/cert-hash

module SSL;

export {
	redef enum Notice::Type += {
		## Indicates that the common name (CN) in the subject field contains a
		## NUL byte.
		Cert_Contains_NUL_byte
	};
}

event x509_certificate(c: connection, is_orig: bool, cert: X509, 
    chain_idx: count, chain_len: count, der_cert: string) &priority=3
	{
	if ( ! c$ssl?$subject )
		return;

    local cn = extract_asn1_value(c$ssl$subject, "CN");

	if ( /\x00/ in cn )
	    {
		local msg = fmt("SSL certificate with NUL byte in subject CN (%s)", cn);
		NOTICE([$note=Cert_Contains_NUL_byte, $msg=msg,
		        $sub=c$ssl$subject, $conn=c,
		        $identifier=cat(c$id$resp_h, c$id$resp_p, c$ssl$validation_status,
		            c$ssl$cert_hash)]);
		}
	}
