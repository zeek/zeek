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
			Intel::seen([$indicator=email,
			             $indicator_type=Intel::EMAIL,
			             $conn=c,
			             $where=(is_orig ? SSL::IN_CLIENT_CERT : SSL::IN_SERVER_CERT)]);
			}

		Intel::seen([$indicator=sha1_hash(der_cert),
		             $indicator_type=Intel::CERT_HASH,
		             $conn=c,
		             $where=(is_orig ? SSL::IN_CLIENT_CERT : SSL::IN_SERVER_CERT)]);
		}
	}

event ssl_extension(c: connection, is_orig: bool, code: count, val: string)
	{
	if ( is_orig && SSL::extensions[code] == "server_name" && 
	     c?$ssl && c$ssl?$server_name )
		Intel::seen([$indicator=c$ssl$server_name,
		             $indicator_type=Intel::DOMAIN,
		             $conn=c,
		             $where=SSL::IN_SERVER_NAME]);
	}
