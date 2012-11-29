@load base/frameworks/intel
@load base/protocols/ssl
@load ./where-locations

event x509_certificate(c: connection, is_orig: bool, cert: X509, chain_idx: count, chain_len: count, der_cert: string)
	{
	if ( chain_idx == 0 )
		{
		if ( /emailAddress=/ in cert$subject )
			{
			local email = sub(cert$subject, /^.*emailAddress=/, "");
			email = sub(email, /,.*$/, "");
			Intel::seen([$str=email,
			             $str_type=Intel::EMAIL,
			             $conn=c,
			             $where=(is_orig ? SSL::IN_CLIENT_CERT : SSL::IN_SERVER_CERT)]);
			}

		Intel::seen([$str=sha1_hash(der_cert),
		             $str_type=Intel::CERT_HASH,
		             $conn=c,
		             $where=(is_orig ? SSL::IN_CLIENT_CERT : SSL::IN_SERVER_CERT)]);
		}
	}

event ssl_extension(c: connection, is_orig: bool, code: count, val: string)
	{
	if ( is_orig && SSL::extensions[code] == "server_name" && 
	     c?$ssl && c$ssl?$server_name )
		Intel::seen([$str=c$ssl$server_name,
		             $str_type=Intel::DOMAIN,
		             $conn=c,
		             $where=SSL::IN_SERVER_NAME]);
	}
