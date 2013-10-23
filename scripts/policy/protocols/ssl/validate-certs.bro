##! Perform full certificate chain validation for SSL certificates.

@load base/frameworks/notice
@load base/protocols/ssl
@load protocols/ssl/cert-hash

module SSL;

export {
	redef enum Notice::Type += {
		## This notice indicates that the result of validating the
		## certificate along with its full certificate chain was
		## invalid.
		Invalid_Server_Cert
	};
	
	redef record Info += {
		## Result of certificate validation for this connection.
		validation_status: string &log &optional;
	};
	
	## MD5 hash values for recently validated certs along with the
	## validation status message are kept in this table to avoid constant
	## validation every time the same certificate is seen.
	global recently_validated_certs: table[string] of string = table() 
		&read_expire=5mins &synchronized &redef;
}

event ssl_established(c: connection) &priority=3
	{
	# If there aren't any certs we can't very well do certificate validation.
	if ( ! c$ssl?$cert || ! c$ssl?$cert_chain )
		return;
	
	if ( c$ssl?$cert_hash && c$ssl$cert_hash in recently_validated_certs )
		{
		c$ssl$validation_status = recently_validated_certs[c$ssl$cert_hash];
		}
	else
		{
		local result = x509_verify(c$ssl$cert, c$ssl$cert_chain, root_certs);
		c$ssl$validation_status = x509_err2str(result);
		}
		
	if ( c$ssl$validation_status != "ok" )
		{
		local message = fmt("SSL certificate validation failed with (%s)", c$ssl$validation_status);
		NOTICE([$note=Invalid_Server_Cert, $msg=message,
		        $sub=c$ssl$subject, $conn=c,
		        $identifier=cat(c$id$resp_h,c$id$resp_p,c$ssl$validation_status,c$ssl$cert_hash)]);
		}
	}


