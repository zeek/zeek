@load base/frameworks/notice/main
@load base/protocols/ssl/main

module SSL;

export {
	redef enum Notice::Type += {
		Invalid_Server_Cert
	};
	
	redef record Info += {
		validation_status: string &log &optional;
	};

}

event ssl_established(c: connection) &priority=5
	{
	# If there aren't any certs we can't very well do certificate validation.
	if ( !c$ssl?$cert || !c$ssl?$cert_chain )
		return;
		
	local result = x509_verify(c$ssl$cert, c$ssl$cert_chain, root_certs);
	c$ssl$validation_status = x509_err2str(result);
	if ( result != 0 )
		{
		local message = fmt("SSL certificate validation failed with (%s)", c$ssl$validation_status);
		NOTICE([$note=Invalid_Server_Cert, $msg=message,
		        $sub=c$ssl$subject, $conn=c]);
		}
	}


