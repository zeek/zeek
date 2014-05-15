##! Perform full certificate chain validation for SSL certificates.

@load base/frameworks/notice
@load base/protocols/ssl

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
	
	## MD5 hash values for recently validated chains along with the
	## validation status message are kept in this table to avoid constant
	## validation every time the same certificate chain is seen.
	global recently_validated_certs: table[string] of string = table() 
		&read_expire=5mins &synchronized &redef;
}

event ssl_established(c: connection) &priority=3
	{
	# If there aren't any certs we can't very well do certificate validation.
	if ( ! c$ssl?$cert_chain || |c$ssl$cert_chain| == 0 )
		return;

	local chain_id = join_string_vec(c$ssl$cert_chain_fuids, ".");

	local chain: vector of opaque of x509 = vector();
	for ( i in c$ssl$cert_chain )
		{
		chain[i] = c$ssl$cert_chain[i]$x509$handle;
		}

	if ( chain_id in recently_validated_certs )
		{
		c$ssl$validation_status = recently_validated_certs[chain_id];
		}
	else
		{
		local result = x509_verify(chain, root_certs);
		c$ssl$validation_status = result$result_string;
		recently_validated_certs[chain_id] = result$result_string;
		}
		
	if ( c$ssl$validation_status != "ok" )
		{
		local message = fmt("SSL certificate validation failed with (%s)", c$ssl$validation_status);
		NOTICE([$note=Invalid_Server_Cert, $msg=message,
		        $sub=c$ssl$subject, $conn=c,
		        $identifier=cat(c$id$resp_h,c$id$resp_p,c$ssl$validation_status)]);
		}
	}


