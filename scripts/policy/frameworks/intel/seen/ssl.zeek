@load base/frameworks/intel
@load base/protocols/ssl
@load ./where-locations

event ssl_extension_server_name(c: connection, is_orig: bool, names: string_vec)
	{
	if ( is_orig && c?$ssl && c$ssl?$server_name )
		Intel::seen([$indicator=c$ssl$server_name,
		             $indicator_type=Intel::DOMAIN,
		             $conn=c,
		             $where=SSL::IN_SERVER_NAME]);
	}

event ssl_established(c: connection)
	{
	if ( ! c$ssl?$cert_chain || |c$ssl$cert_chain| == 0 ||
	     ! c$ssl$cert_chain[0]?$x509 )
		return;

	if ( c$ssl$cert_chain[0]$x509?$certificate && c$ssl$cert_chain[0]$x509$certificate?$cn )
		Intel::seen([$indicator=c$ssl$cert_chain[0]$x509$certificate$cn,
			$indicator_type=Intel::DOMAIN,
			$fuid=c$ssl$cert_chain[0]$fuid,
			$conn=c,
			$where=X509::IN_CERT]);
	}
