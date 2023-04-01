##! When the server requests a client certificate, it optionally may specify a list of CAs that
##! it accepts. If the server does this, this script adds this list to ssl.log.

@load base/protocols/ssl

module SSL;

redef record SSL::Info += {
	## List of cient certificate CAs accepted by the server
	requested_client_certificate_authorities: vector of string &optional &log;
};

event ssl_certificate_request(c: connection, is_client: bool, certificate_types: index_vec, supported_signature_algorithms: signature_and_hashalgorithm_vec, certificate_authorities: string_vec)
	{
	if ( is_client )
		return;

	local out: vector of string = vector();
	for ( _, ca in certificate_authorities )
		out += parse_distinguished_name(ca);

	c$ssl$requested_client_certificate_authorities = out;
	}
